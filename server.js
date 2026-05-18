import crypto from "node:crypto";
import dns from "node:dns/promises";
import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

import * as cheerio from "cheerio";
import mime from "mime-types";
import { CookieJar } from "tough-cookie";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.join(__dirname, "public");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number.parseInt(process.env.PORT || "8080", 10);
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === "1";
const DEBUG_PROXY = process.env.DEBUG_PROXY === "1";
const MAX_BODY_BYTES = 25 * 1024 * 1024;
const SESSION_COOKIE = "horizon_sid";
const SESSION_TTL_MS = 6 * 60 * 60 * 1000;

const sessions = new Map();

class HttpError extends Error {
  constructor(status, title, detail) {
    super(detail || title);
    this.status = status;
    this.title = title;
    this.detail = detail || title;
  }
}

const server = http.createServer(async (req, res) => {
  try {
    await route(req, res);
  } catch (error) {
    if (error instanceof HttpError) {
      sendError(res, error.status, error.title, error.detail);
      return;
    }

    console.error(error);
    sendError(res, 500, "Proxy error", "The proxy hit an unexpected error while handling the request.");
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Horizon Proxy running at http://${HOST}:${PORT}`);
  if (!ALLOW_PRIVATE) {
    console.log("Private and localhost targets are blocked. Set ALLOW_PRIVATE=1 to opt in.");
  }
});

setInterval(cleanupSessions, 30 * 60 * 1000).unref();

async function route(req, res) {
  const requestUrl = new URL(req.url || "/", `http://${req.headers.host || `${HOST}:${PORT}`}`);
  const pathname = decodeURIComponent(requestUrl.pathname);

  if (req.method === "OPTIONS") {
    send(res, 204, corsHeaders(), "");
    return;
  }

  if (pathname === "/health") {
    sendJson(res, 200, {
      ok: true,
      allowPrivate: ALLOW_PRIVATE,
      sessions: sessions.size
    });
    return;
  }

  if (pathname === "/go") {
    handleGo(requestUrl, res);
    return;
  }

  if (pathname.startsWith("/p/")) {
    await handleProxy(req, res, requestUrl);
    return;
  }

  if (pathname === "/") {
    await serveStatic(res, path.join(PUBLIC_DIR, "index.html"));
    return;
  }

  if (await tryServeStatic(res, path.join(PUBLIC_DIR, pathname))) {
    return;
  }

  const contextTarget = inferContextTarget(req, requestUrl);
  if (contextTarget) {
    await handleProxyTarget(req, res, contextTarget);
    return;
  }

  sendError(res, 404, "Not found", "That proxy resource does not exist.");
}

function handleGo(requestUrl, res) {
  const input = requestUrl.searchParams.get("url") || "";
  const target = normalizeTargetInput(input);
  sendRedirect(res, proxiedUrl(target.href));
}

async function handleProxy(req, res, requestUrl) {
  const encoded = requestUrl.pathname.slice("/p/".length);
  const decoded = decodeTargetUrl(encoded);
  if (!decoded) {
    throw new HttpError(400, "Bad proxy URL", "This proxy URL is missing or malformed.");
  }

  const target = new URL(decoded);
  if (req.method === "GET" && requestUrl.search) {
    for (const [name, value] of requestUrl.searchParams) {
      target.searchParams.append(name, value);
    }
  }

  await handleProxyTarget(req, res, target);
}

async function handleProxyTarget(req, res, target) {
  validateProtocol(target);
  await assertTargetAllowed(target);

  const { session, setCookie } = getSession(req);
  session.lastTarget = target.href;
  session.lastOrigin = target.origin;

  if (isBlockedAdRequest(target)) {
    sendBlockedAdResponse(req, res, target, setCookie);
    return;
  }

  const upstream = await fetchUpstream(req, target, session.jar);
  await storeUpstreamCookies(session.jar, target.href, upstream.headers);

  if (isRedirect(upstream.status)) {
    const location = upstream.headers.get("location");
    if (location) {
      const nextTarget = new URL(location, target);
      sendRedirect(res, proxiedUrl(nextTarget.href), setCookie, upstream.status);
      return;
    }
  }

  const contentType = upstream.headers.get("content-type") || "application/octet-stream";
  const headers = filteredResponseHeaders(upstream.headers, target);
  if (setCookie) {
    headers["set-cookie"] = setCookie;
  }

  if (req.method === "HEAD") {
    debugRequest(req, target, upstream, contentType);
    send(res, upstream.status, headers, "");
    return;
  }

  if (isHtml(contentType)) {
    const html = await upstream.text();
    const rewritten = rewriteHtml(html, target);
    headers["content-type"] = "text/html; charset=utf-8";
    headers["content-length"] = Buffer.byteLength(rewritten);
    debugRequest(req, target, upstream, contentType);
    send(res, upstream.status, headers, rewritten);
    return;
  }

  if (isCss(contentType)) {
    const css = await upstream.text();
    const rewritten = rewriteCss(css, target);
    headers["content-type"] = "text/css; charset=utf-8";
    headers["content-length"] = Buffer.byteLength(rewritten);
    debugRequest(req, target, upstream, contentType);
    send(res, upstream.status, headers, rewritten);
    return;
  }

  debugRequest(req, target, upstream, contentType);
  send(res, upstream.status, headers);
  if (!upstream.body) {
    res.end();
    return;
  }

  Readable.fromWeb(upstream.body).pipe(res);
}

function inferContextTarget(req, requestUrl) {
  const refererTarget = targetReferer(req.headers.referer);
  if (refererTarget) {
    try {
      return new URL(`${requestUrl.pathname}${requestUrl.search}`, refererTarget);
    } catch {
      return null;
    }
  }

  const session = getExistingSession(req);
  if (!session?.lastOrigin) {
    return null;
  }

  try {
    return new URL(`${requestUrl.pathname}${requestUrl.search}`, session.lastOrigin);
  } catch {
    return null;
  }
}

async function fetchUpstream(req, target, jar) {
  const headers = await makeForwardHeaders(req, target, jar);
  const init = {
    method: req.method,
    headers,
    redirect: "manual",
    signal: AbortSignal.timeout(35000)
  };

  if (!["GET", "HEAD"].includes(req.method || "GET")) {
    init.body = await readRequestBody(req);
  }

  try {
    return await fetch(target, init);
  } catch (error) {
    if (error.name === "TimeoutError") {
      throw new HttpError(504, "Upstream timed out", `The request to ${target.hostname} took too long.`);
    }

    throw new HttpError(502, "Upstream request failed", `The proxy could not reach ${target.hostname}.`);
  }
}

async function makeForwardHeaders(req, target, jar) {
  const headers = {};
  const skip = new Set([
    "accept-encoding",
    "connection",
    "content-length",
    "cookie",
    "host",
    "keep-alive",
    "origin",
    "proxy-authenticate",
    "proxy-authorization",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade"
  ]);

  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (skip.has(lower)) {
      continue;
    }

    headers[lower] = Array.isArray(value) ? value.join(", ") : value;
  }

  headers["accept"] ||= "*/*";
  headers["accept-encoding"] = "identity";
  headers["user-agent"] ||= "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HorizonProxy/1.0 Safari/537.36";

  const cookie = await getJarCookieString(jar, target.href);
  if (cookie) {
    headers.cookie = cookie;
  }

  const referer = targetReferer(req.headers.referer);
  if (referer) {
    headers.referer = referer;
  }

  if (req.headers.origin) {
    headers.origin = target.origin;
  }

  return headers;
}

function targetReferer(refererHeader) {
  if (!refererHeader) {
    return "";
  }

  try {
    const refererUrl = new URL(refererHeader);
    if (!refererUrl.pathname.startsWith("/p/")) {
      return "";
    }

    return decodeTargetUrl(refererUrl.pathname.slice("/p/".length)) || "";
  } catch {
    return "";
  }
}

async function readRequestBody(req) {
  const chunks = [];
  let size = 0;

  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      throw new HttpError(413, "Body too large", "This proxy limits forwarded request bodies to 25 MB.");
    }

    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

function rewriteHtml(html, target) {
  const $ = cheerio.load(html, { decodeEntities: false });

  $("meta[http-equiv]").each((_, element) => {
    const header = ($(element).attr("http-equiv") || "").toLowerCase();
    if (header === "content-security-policy") {
      $(element).remove();
      return;
    }

    if (header === "refresh") {
      const content = $(element).attr("content");
      if (content) {
        $(element).attr("content", rewriteMetaRefresh(content, target));
      }
    }
  });

  const attrMap = [
    ["a", "href"],
    ["area", "href"],
    ["audio", "src"],
    ["embed", "src"],
    ["form", "action"],
    ["iframe", "src"],
    ["img", "src"],
    ["input", "src"],
    ["link", "href"],
    ["object", "data"],
    ["script", "src"],
    ["source", "src"],
    ["track", "src"],
    ["video", "poster"],
    ["video", "src"]
  ];

  for (const [selector, attr] of attrMap) {
    $(`${selector}[${attr}]`).each((_, element) => {
      const current = $(element).attr(attr);
      $(element).attr(attr, rewriteUrl(current, target));
    });
  }

  $("[srcset]").each((_, element) => {
    const current = $(element).attr("srcset");
    $(element).attr("srcset", rewriteSrcset(current, target));
  });

  $("[style]").each((_, element) => {
    const style = $(element).attr("style");
    $(element).attr("style", rewriteCss(style || "", target));
  });

  $("style").each((_, element) => {
    const css = $(element).html() || "";
    $(element).text(rewriteCss(css, target));
  });

  $("script[integrity], link[integrity]").removeAttr("integrity").removeAttr("crossorigin");

  const client = `<script data-horizon-client>${clientScript(target.href)}</script>`;
  if ($("head").length) {
    $("head").prepend(client);
  } else {
    $.root().prepend(client);
  }

  return $.html();
}

function rewriteMetaRefresh(content, target) {
  return content.replace(/(^\s*\d+\s*;\s*url=)(.+)$/i, (_, prefix, rawUrl) => {
    return `${prefix}${rewriteUrl(rawUrl.trim().replace(/^['"]|['"]$/g, ""), target)}`;
  });
}

function rewriteSrcset(srcset, target) {
  if (!srcset) {
    return srcset;
  }

  return srcset
    .split(",")
    .map((part) => {
      const trimmed = part.trim();
      if (!trimmed) {
        return trimmed;
      }

      const [rawUrl, ...descriptor] = trimmed.split(/\s+/);
      return [rewriteUrl(rawUrl, target), ...descriptor].join(" ");
    })
    .join(", ");
}

function rewriteCss(css, target) {
  if (!css) {
    return css;
  }

  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (match, quote, rawUrl) => {
      if (!rawUrl || shouldSkipRewrite(rawUrl)) {
        return match;
      }

      const rewritten = rewriteUrl(rawUrl, target);
      const safeQuote = quote || '"';
      return `url(${safeQuote}${rewritten}${safeQuote})`;
    })
    .replace(/@import\s+(?:url\(\s*)?(['"])(.*?)\1\s*\)?/gi, (match, quote, rawUrl) => {
      if (!rawUrl || shouldSkipRewrite(rawUrl)) {
        return match;
      }

      return match.replace(rawUrl, rewriteUrl(rawUrl, target));
    });
}

function rewriteUrl(value, target) {
  if (!value) {
    return value;
  }

  const raw = String(value).trim();
  if (!raw || shouldSkipRewrite(raw)) {
    return value;
  }

  try {
    const absolute = new URL(raw, target);
    if (!["http:", "https:"].includes(absolute.protocol)) {
      return value;
    }

    return proxiedUrl(absolute.href);
  } catch {
    return value;
  }
}

function shouldSkipRewrite(value) {
  return (
    value.startsWith("#") ||
    value.startsWith("/p/") ||
    /^(?:about|blob|data|javascript|mailto|sms|tel|urn|webcal):/i.test(value)
  );
}

function clientScript(targetHref) {
  const targetJson = JSON.stringify(targetHref).replace(/</g, "\\u003c");

  return `
(() => {
  if (window.__HORIZON_PROXY_ACTIVE__) return;
  window.__HORIZON_PROXY_ACTIVE__ = true;

  const target = ${targetJson};
  const skip = /^(?:about|blob|data|javascript|mailto|sms|tel|urn|webcal):/i;

  function encodeUrl(value) {
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
  }

  function isAlreadyProxied(value) {
    try {
      const url = new URL(value, location.href);
      return url.origin === location.origin && url.pathname.startsWith("/p/");
    } catch {
      return false;
    }
  }

  function proxify(value) {
    if (!value || skip.test(value) || String(value).startsWith("#") || isAlreadyProxied(value)) {
      return value;
    }

    try {
      return "/p/" + encodeUrl(new URL(value, target).href);
    } catch {
      return value;
    }
  }

  const nativeFetch = window.fetch && window.fetch.bind(window);
  if (nativeFetch) {
    window.fetch = (input, init) => {
      if (typeof input === "string" || input instanceof URL) {
        return nativeFetch(proxify(String(input)), init);
      }

      if (input instanceof Request) {
        return nativeFetch(new Request(proxify(input.url), input), init);
      }

      return nativeFetch(input, init);
    };
  }

  const nativeOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    return nativeOpen.call(this, method, proxify(url), ...rest);
  };

  const nativeWindowOpen = window.open;
  window.open = function(url, name, features) {
    return nativeWindowOpen.call(window, proxify(url), name, features);
  };

  const nativePushState = history.pushState && history.pushState.bind(history);
  if (nativePushState) {
    history.pushState = function(state, title, url) {
      return nativePushState(state, title, url == null ? url : proxify(String(url)));
    };
  }

  const nativeReplaceState = history.replaceState && history.replaceState.bind(history);
  if (nativeReplaceState) {
    history.replaceState = function(state, title, url) {
      return nativeReplaceState(state, title, url == null ? url : proxify(String(url)));
    };
  }

  try {
    const nativeAssign = Location.prototype.assign;
    const nativeReplace = Location.prototype.replace;
    Object.defineProperty(Location.prototype, "assign", {
      configurable: true,
      value(url) {
        return nativeAssign.call(this, proxify(String(url)));
      }
    });
    Object.defineProperty(Location.prototype, "replace", {
      configurable: true,
      value(url) {
        return nativeReplace.call(this, proxify(String(url)));
      }
    });
  } catch {}

  if (window.EventSource) {
    const NativeEventSource = window.EventSource;
    window.EventSource = function(url, config) {
      return new NativeEventSource(proxify(url), config);
    };
  }

  if (window.Worker) {
    const NativeWorker = window.Worker;
    window.Worker = function(url, options) {
      return new NativeWorker(proxify(url), options);
    };
  }

  function rewriteForm(form) {
    if (!form || form.tagName !== "FORM") return;
    const action = form.getAttribute("action") || target;
    form.setAttribute("action", proxify(action));
  }

  if (window.HTMLFormElement) {
    const nativeSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
      rewriteForm(this);
      return nativeSubmit.call(this);
    };

    const nativeRequestSubmit = HTMLFormElement.prototype.requestSubmit;
    if (nativeRequestSubmit) {
      HTMLFormElement.prototype.requestSubmit = function(submitter) {
        rewriteForm(this);
        return submitter ? nativeRequestSubmit.call(this, submitter) : nativeRequestSubmit.call(this);
      };
    }
  }

  function rewriteElement(element) {
    if (!element || element.nodeType !== 1) return;
    for (const attr of ["href", "src", "action", "poster", "data"]) {
      if (element.hasAttribute(attr)) {
        const value = element.getAttribute(attr);
        const next = proxify(value);
        if (next !== value) element.setAttribute(attr, next);
      }
    }

    if (element.hasAttribute("srcset")) {
      element.setAttribute("srcset", element.getAttribute("srcset").split(",").map((part) => {
        const bits = part.trim().split(/\\s+/);
        if (!bits[0]) return part;
        bits[0] = proxify(bits[0]);
        return bits.join(" ");
      }).join(", "));
    }
  }

  document.addEventListener("click", (event) => {
    const anchor = event.target.closest && event.target.closest("a[href]");
    if (anchor) rewriteElement(anchor);
  }, true);

  document.addEventListener("submit", (event) => {
    rewriteForm(event.target);
  }, true);

  new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.type === "attributes") {
        rewriteElement(mutation.target);
      }

      for (const node of mutation.addedNodes || []) {
        rewriteElement(node);
        if (node.querySelectorAll) {
          node.querySelectorAll("[href], [src], [action], [poster], [data]").forEach(rewriteElement);
        }
      }
    }
  }).observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["href", "src", "action", "poster", "data"]
  });

  function mountToolbar() {
    if (!document.documentElement || document.getElementById("__horizon_proxy_toolbar")) return;
    const host = document.createElement("div");
    host.id = "__horizon_proxy_toolbar";
    host.style.cssText = "position:fixed;left:16px;right:16px;bottom:16px;z-index:2147483647;pointer-events:none;";
    const shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML = \`
      <style>
        :host, * { box-sizing: border-box; }
        form {
          pointer-events: auto;
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto auto;
          gap: 8px;
          width: min(840px, 100%);
          margin: 0 auto;
          padding: 8px;
          border: 1px solid rgba(20, 24, 31, .16);
          border-radius: 8px;
          background: rgba(255, 255, 255, .96);
          box-shadow: 0 10px 26px rgba(20, 24, 31, .18);
          font: 14px/1.4 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        input {
          min-width: 0;
          height: 36px;
          border: 1px solid rgba(20, 24, 31, .22);
          border-radius: 6px;
          padding: 0 10px;
          color: #171a20;
          background: #fff;
          font: inherit;
        }
        button, a {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          min-width: 52px;
          height: 36px;
          border: 1px solid #157a74;
          border-radius: 6px;
          padding: 0 12px;
          color: #fff;
          background: #157a74;
          font: inherit;
          text-decoration: none;
          cursor: pointer;
        }
        a {
          min-width: 64px;
          border-color: rgba(20, 24, 31, .22);
          color: #171a20;
          background: #f5f7f9;
        }
        @media (max-width: 560px) {
          form { grid-template-columns: 1fr auto; }
          a { display: none; }
        }
      </style>
      <form>
        <input aria-label="Proxy address" value="\${target.replace(/"/g, "&quot;")}" spellcheck="false" />
        <button type="submit">Go</button>
        <a href="/">Home</a>
      </form>
    \`;
    shadow.querySelector("form").addEventListener("submit", (event) => {
      event.preventDefault();
      const input = shadow.querySelector("input");
      if (input.value.trim()) {
        location.href = "/go?url=" + encodeURIComponent(input.value.trim());
      }
    });
    document.documentElement.appendChild(host);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountToolbar, { once: true });
  } else {
    mountToolbar();
  }
})();
`;
}

function filteredResponseHeaders(headers, target) {
  const result = {
    "access-control-allow-origin": "*",
    "x-horizon-target": target.origin
  };
  const skip = new Set([
    "clear-site-data",
    "connection",
    "content-encoding",
    "content-length",
    "content-security-policy",
    "content-security-policy-report-only",
    "location",
    "nel",
    "permissions-policy",
    "proxy-authenticate",
    "public-key-pins",
    "report-to",
    "set-cookie",
    "strict-transport-security",
    "transfer-encoding",
    "upgrade",
    "x-content-security-policy",
    "x-frame-options",
    "x-webkit-csp"
  ]);

  for (const [name, value] of headers) {
    const lower = name.toLowerCase();
    if (!skip.has(lower)) {
      result[lower] = value;
    }
  }

  return result;
}

function isBlockedAdRequest(target) {
  const hostname = target.hostname.toLowerCase();
  const pathname = target.pathname.toLowerCase();

  if (
    hostname.endsWith("doubleclick.net") ||
    hostname.endsWith("googleadservices.com") ||
    hostname.endsWith("googlesyndication.com")
  ) {
    return true;
  }

  if (hostname.endsWith("youtube.com")) {
    return (
      pathname.includes("/pagead/") ||
      pathname.includes("/ptracking") ||
      pathname.includes("/api/stats/ads") ||
      pathname.includes("/get_midroll_")
    );
  }

  return false;
}

function sendBlockedAdResponse(req, res, target, setCookie) {
  debugBlockedRequest(req, target);

  const headers = {
    "access-control-allow-origin": "*",
    "cache-control": "no-store",
    "x-horizon-blocked": "ad"
  };
  if (setCookie) {
    headers["set-cookie"] = setCookie;
  }

  const pathname = target.pathname.toLowerCase();
  if (pathname.endsWith(".js")) {
    headers["content-type"] = "text/javascript; charset=utf-8";
    send(res, 200, headers, "");
    return;
  }

  if (pathname.endsWith(".json") || pathname.includes("/pagead/")) {
    headers["content-type"] = "application/json; charset=utf-8";
    send(res, 200, headers, "{}");
    return;
  }

  send(res, 204, headers, "");
}

function debugBlockedRequest(req, target) {
  if (!DEBUG_PROXY) {
    return;
  }

  console.log(`${new Date().toISOString()} ${req.method} ${target.href} -> blocked`);
}

function debugRequest(req, target, upstream, contentType) {
  if (!DEBUG_PROXY) {
    return;
  }

  const range = req.headers.range ? ` range=${req.headers.range}` : "";
  console.log(`${new Date().toISOString()} ${req.method} ${target.href} -> ${upstream.status} ${contentType}${range}`);
}

function getSession(req) {
  const cookies = parseCookieHeader(req.headers.cookie || "");
  let id = cookies[SESSION_COOKIE];
  let setCookie = "";

  if (!id || !sessions.has(id)) {
    id = crypto.randomBytes(18).toString("base64url");
    sessions.set(id, { jar: new CookieJar(), lastSeen: Date.now() });
    setCookie = `${SESSION_COOKIE}=${id}; HttpOnly; SameSite=Lax; Path=/`;
  }

  const session = sessions.get(id);
  session.lastSeen = Date.now();
  return { session, setCookie };
}

function getExistingSession(req) {
  const cookies = parseCookieHeader(req.headers.cookie || "");
  const id = cookies[SESSION_COOKIE];
  if (!id) {
    return null;
  }

  const session = sessions.get(id);
  if (session) {
    session.lastSeen = Date.now();
  }

  return session || null;
}

function cleanupSessions() {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.lastSeen > SESSION_TTL_MS) {
      sessions.delete(id);
    }
  }
}

function parseCookieHeader(header) {
  return Object.fromEntries(
    header
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf("=");
        if (index === -1) {
          return [part, ""];
        }

        return [part.slice(0, index), part.slice(index + 1)];
      })
  );
}

async function getJarCookieString(jar, url) {
  return new Promise((resolve, reject) => {
    jar.getCookieString(url, {}, (error, cookies) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(cookies);
    });
  });
}

async function storeUpstreamCookies(jar, url, headers) {
  const setCookies = getSetCookies(headers);
  await Promise.all(
    setCookies.map(
      (cookie) =>
        new Promise((resolve) => {
          jar.setCookie(cookie, url, { ignoreError: true }, () => resolve());
        })
    )
  );
}

function getSetCookies(headers) {
  if (typeof headers.getSetCookie === "function") {
    return headers.getSetCookie();
  }

  const cookie = headers.get("set-cookie");
  if (!cookie) {
    return [];
  }

  return cookie.split(/,(?=\s*[^;,\s]+=)/g);
}

function normalizeTargetInput(input) {
  const value = String(input || "").trim();
  if (!value) {
    throw new HttpError(400, "Missing URL", "Enter a URL or search query to open through the proxy.");
  }

  const hasScheme = /^[a-z][a-z\d+.-]*:/i.test(value);
  const candidate = hasScheme
    ? value
    : looksLikeHost(value)
      ? `https://${value}`
      : `https://duckduckgo.com/html/?q=${encodeURIComponent(value)}`;

  let target;
  try {
    target = new URL(candidate);
  } catch {
    throw new HttpError(400, "Invalid URL", "That address could not be parsed as a web URL.");
  }

  validateProtocol(target);
  return target;
}

function looksLikeHost(value) {
  return !/\s/.test(value) && (value.includes(".") || value.includes(":") || value.startsWith("localhost"));
}

function validateProtocol(target) {
  if (!["http:", "https:"].includes(target.protocol)) {
    throw new HttpError(400, "Unsupported protocol", "Only HTTP and HTTPS URLs can be proxied.");
  }
}

async function assertTargetAllowed(target) {
  if (ALLOW_PRIVATE) {
    return;
  }

  const hostname = target.hostname.toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    throw privateTargetError(target);
  }

  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) {
      throw privateTargetError(target);
    }
    return;
  }

  let records;
  try {
    records = await dns.lookup(hostname, { all: true });
  } catch {
    throw new HttpError(502, "DNS lookup failed", `The proxy could not resolve ${hostname}.`);
  }

  if (records.some((record) => isPrivateAddress(record.address))) {
    throw privateTargetError(target);
  }
}

function privateTargetError(target) {
  return new HttpError(
    403,
    "Private target blocked",
    `${target.hostname} resolves to a private or local network address. Set ALLOW_PRIVATE=1 only when you trust the target.`
  );
}

function isPrivateAddress(address) {
  const version = net.isIP(address);
  if (version === 4) {
    const parts = address.split(".").map(Number);
    const [a, b] = parts;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19))
    );
  }

  if (version === 6) {
    const lower = address.toLowerCase();
    return (
      lower === "::" ||
      lower === "::1" ||
      lower.startsWith("fc") ||
      lower.startsWith("fd") ||
      /^fe[89ab]/.test(lower) ||
      lower.startsWith("::ffff:127.") ||
      lower.startsWith("::ffff:10.") ||
      lower.startsWith("::ffff:192.168.")
    );
  }

  return true;
}

function isRedirect(status) {
  return [301, 302, 303, 307, 308].includes(status);
}

function isHtml(contentType) {
  return /(?:^|;)\s*(?:text\/html|application\/xhtml\+xml)\b/i.test(contentType);
}

function isCss(contentType) {
  return /(?:^|;)\s*text\/css\b/i.test(contentType);
}

function proxiedUrl(targetHref) {
  return `/p/${encodeTargetUrl(targetHref)}`;
}

function encodeTargetUrl(targetHref) {
  return Buffer.from(targetHref, "utf8").toString("base64url");
}

function decodeTargetUrl(encoded) {
  try {
    return Buffer.from(encoded, "base64url").toString("utf8");
  } catch {
    return "";
  }
}

async function serveStatic(res, filePath) {
  if (await tryServeStatic(res, filePath)) {
    return;
  }

  sendError(res, 404, "Not found", "That proxy resource does not exist.");
}

async function tryServeStatic(res, filePath) {
  const resolved = path.resolve(filePath);
  if (!isPublicPath(resolved)) {
    return false;
  }

  try {
    const stat = await fs.stat(resolved);
    if (!stat.isFile()) {
      return false;
    }

    const data = await fs.readFile(resolved);
    const contentType = mime.lookup(resolved) || "application/octet-stream";
    send(res, 200, {
      "cache-control": "public, max-age=600",
      "content-length": data.length,
      "content-type": contentType
    }, data);
    return true;
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "EISDIR") {
      return false;
    }

    throw error;
  }
}

function isPublicPath(resolved) {
  const relative = path.relative(PUBLIC_DIR, resolved);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function sendJson(res, status, body) {
  send(res, status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8"
  }, JSON.stringify(body));
}

function sendRedirect(res, location, setCookie = "", status = 302) {
  const headers = {
    "cache-control": "no-store",
    location
  };
  if (setCookie) {
    headers["set-cookie"] = setCookie;
  }

  send(res, status, headers, "");
}

function sendError(res, status, title, detail) {
  if (res.headersSent) {
    res.end();
    return;
  }

  const body = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} - Horizon Proxy</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <main class="error-shell">
    <a class="home-link" href="/">Horizon Proxy</a>
    <section class="error-panel">
      <p class="eyebrow">${status}</p>
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(detail)}</p>
      <form class="inline-proxy-form" action="/go" method="get">
        <input name="url" aria-label="Proxy address" placeholder="https://example.com" />
        <button type="submit">Go</button>
      </form>
    </section>
  </main>
</body>
</html>`;
  send(res, status, {
    "cache-control": "no-store",
    "content-type": "text/html; charset=utf-8"
  }, body);
}

function send(res, status, headers = {}, body) {
  res.writeHead(status, headers);
  if (body === undefined) {
    return;
  }

  res.end(body);
}

function corsHeaders() {
  return {
    "access-control-allow-headers": "content-type",
    "access-control-allow-methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "access-control-allow-origin": "*"
  };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
