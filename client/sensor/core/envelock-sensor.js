/*
 * Envelock sensor — the shared core.
 *
 * One file, loaded unchanged by every client:
 *   - the browser extension's background (Chrome service worker via
 *     importScripts, Firefox background page),
 *   - the Thunderbird add-on's background page,
 *   - the Outlook add-in's task pane,
 *   - and the Node test suite, which imports it for its side effect.
 *
 * That is why it has no `import`/`export`: a file without them is both a valid
 * classic script and a valid ES module, so no build step can drift the clients
 * apart. Everything is exposed on `globalThis.EnvelockSensor`.
 *
 * What a sensor does is deliberately small. It says two things to Envelock,
 * about one mailbox, with a token that can say nothing else:
 *
 *   "this device is here"          → POST /api/v1/sensor/heartbeat
 *   "the owner opened this message" → POST /api/v1/sensor/message-opened
 *
 * From those, the server can tell a sign-in from a new place (C7/C8/C10) and a
 * message read while none of the owner's devices were present (C11). The sensor
 * never reads, stores or sends message content — only the Message-ID header,
 * which is an identifier, not the message.
 */
(function (root) {
  "use strict";

  var DEFAULT_API_BASE = "https://api.envelock.org";

  /* "The owner is reading right now, but this client cannot name the message."
     Most webmail does not expose the Message-ID header. The server accepts this
     as covering any read on the mailbox within its window. */
  var ACTIVITY_REF = "*";

  var HEARTBEAT_SECONDS = 60;

  /* The server accepts an attestation for 180s either side of a read. One that
     is older than this by the time it can be delivered is noise, so it is
     dropped rather than sent late. */
  var ATTEST_MAX_AGE_MS = 150 * 1000;

  var KEY_DEVICE = "envelock.deviceId";
  var KEY_ENROLLMENTS = "envelock.enrollments";

  /* ── Pure helpers ──────────────────────────────────────────────────────── */

  /* Mirrors platform/sensor.normalize_message_ref on the server exactly:
     trimmed, unbracketed, lower-cased. Thunderbird hands over the Message-ID
     without angle brackets, Outlook with them; both must name the same message
     the poller sees. */
  function normalizeMessageRef(value) {
    var ref = String(value == null ? "" : value).trim();
    if (ref === ACTIVITY_REF) return ref;
    if (ref.charAt(0) === "<" && ref.charAt(ref.length - 1) === ">") {
      ref = ref.slice(1, -1).trim();
    }
    return ref.toLowerCase().slice(0, 255);
  }

  function normalizeMailbox(value) {
    return String(value == null ? "" : value).trim().toLowerCase();
  }

  /* A random id for this install — not a browser fingerprint. It identifies a
     device to Envelock without identifying the person to anyone else, and the
     server pins the sensor's token to it. */
  function newDeviceId() {
    var c = root.crypto;
    if (c && typeof c.randomUUID === "function") return "dev-" + c.randomUUID();
    var bytes = new Uint8Array(16);
    c.getRandomValues(bytes);
    return (
      "dev-" +
      Array.prototype.map
        .call(bytes, function (b) {
          return ("0" + b.toString(16)).slice(-2);
        })
        .join("")
    );
  }

  /* "Chrome on macOS" — what a person sees in the device list. */
  function describeDevice(userAgent, clientName) {
    var ua = String(userAgent || "");
    var os = /Windows/.test(ua)
      ? "Windows"
      : /Mac OS X|Macintosh/.test(ua)
        ? "macOS"
        : /Android/.test(ua)
          ? "Android"
          : /iPhone|iPad/.test(ua)
            ? "iOS"
            : /CrOS/.test(ua)
              ? "ChromeOS"
              : /Linux/.test(ua)
                ? "Linux"
                : "unknown OS";
    var app = clientName;
    if (!app) {
      app = /Thunderbird\//.test(ua)
        ? "Thunderbird"
        : /Edg\//.test(ua)
          ? "Edge"
          : /Firefox\//.test(ua)
            ? "Firefox"
            : /Chrome\//.test(ua)
              ? "Chrome"
              : /Safari\//.test(ua)
                ? "Safari"
                : "Browser";
    }
    return { label: app + " on " + os, os: os, app: app };
  }

  function SensorError(message, status, revoked) {
    this.name = "SensorError";
    this.message = message;
    this.status = status || 0;
    this.revoked = Boolean(revoked);
  }
  SensorError.prototype = Object.create(Error.prototype);
  SensorError.prototype.constructor = SensorError;

  /* ── Storage ──────────────────────────────────────────────────────────── */

  /* The adapter every client passes in: get/set/remove, all promises. Kept to
     this shape so the browser (storage.local), Thunderbird (storage.local),
     Outlook (localStorage) and tests (a Map) all fit it in a few lines. */
  function memoryStorage(seed) {
    var map = new Map(Object.entries(seed || {}));
    return {
      get: function (key) {
        return Promise.resolve(map.has(key) ? JSON.parse(JSON.stringify(map.get(key))) : undefined);
      },
      set: function (key, value) {
        map.set(key, JSON.parse(JSON.stringify(value)));
        return Promise.resolve();
      },
      remove: function (key) {
        map.delete(key);
        return Promise.resolve();
      },
      dump: function () {
        return Object.fromEntries(map);
      },
    };
  }

  /* browser.storage.local / chrome.storage.local / messenger.storage.local */
  function extensionStorage(area) {
    return {
      get: function (key) {
        return Promise.resolve(area.get(key)).then(function (out) {
          return out ? out[key] : undefined;
        });
      },
      set: function (key, value) {
        var obj = {};
        obj[key] = value;
        return Promise.resolve(area.set(obj));
      },
      remove: function (key) {
        return Promise.resolve(area.remove(key));
      },
    };
  }

  /* window.localStorage — per device, per origin. Used by the Outlook add-in on
     purpose instead of Office roaming settings, which are stored IN the mailbox:
     anyone who got into the mailbox could read the sensor token from there and
     forge the very attestations meant to catch them. */
  function webStorage(ls) {
    return {
      get: function (key) {
        try {
          var raw = ls.getItem(key);
          return Promise.resolve(raw == null ? undefined : JSON.parse(raw));
        } catch (e) {
          return Promise.resolve(undefined);
        }
      },
      set: function (key, value) {
        ls.setItem(key, JSON.stringify(value));
        return Promise.resolve();
      },
      remove: function (key) {
        ls.removeItem(key);
        return Promise.resolve();
      },
    };
  }

  /* ── The client ───────────────────────────────────────────────────────── */

  /**
   * options.storage   adapter (see above)             — required
   * options.client    "browser" | "thunderbird" | "outlook" — required
   * options.fetch     fetch implementation            — defaults to global fetch
   * options.apiBase   Envelock API origin             — defaults to api.envelock.org
   * options.now       clock, for tests
   * options.userAgent for the device label
   */
  function SensorClient(options) {
    if (!options || !options.storage) throw new Error("SensorClient needs a storage adapter");
    if (!options.client) throw new Error("SensorClient needs a client name");
    this.storage = options.storage;
    this.client = options.client;
    this.fetchImpl = options.fetch || (typeof fetch === "function" ? fetch.bind(root) : null);
    this.apiBase = String(options.apiBase || DEFAULT_API_BASE).replace(/\/+$/, "");
    this.now = options.now || Date.now;
    this.userAgent = options.userAgent || (root.navigator && root.navigator.userAgent) || "";
    this.pending = []; /* attestations that failed to send, retried once */
  }

  SensorClient.prototype.deviceId = function () {
    var self = this;
    return this.storage.get(KEY_DEVICE).then(function (existing) {
      if (existing) return existing;
      var id = newDeviceId();
      return self.storage.set(KEY_DEVICE, id).then(function () {
        return id;
      });
    });
  };

  SensorClient.prototype.enrollments = function () {
    return this.storage.get(KEY_ENROLLMENTS).then(function (list) {
      return Array.isArray(list) ? list : [];
    });
  };

  SensorClient.prototype._save = function (list) {
    return this.storage.set(KEY_ENROLLMENTS, list);
  };

  SensorClient.prototype._update = function (mailbox, patch) {
    var self = this;
    var key = normalizeMailbox(mailbox);
    return this.enrollments().then(function (list) {
      var changed = list.map(function (e) {
        return e.mailbox === key ? Object.assign({}, e, patch) : e;
      });
      return self._save(changed).then(function () {
        return changed.find(function (e) {
          return e.mailbox === key;
        });
      });
    });
  };

  SensorClient.prototype._request = function (url, init) {
    if (!this.fetchImpl) return Promise.reject(new SensorError("no network available", 0));
    return this.fetchImpl(url, init).then(
      function (res) {
        return res
          .json()
          .catch(function () {
            return {};
          })
          .then(function (body) {
            if (res.ok) return body;
            var detail = (body && body.detail) || "request failed (" + res.status + ")";
            if (typeof detail !== "string") detail = JSON.stringify(detail);
            /* 401 on a sensor call means the token is gone: removed from the
               dashboard, or its owner's account removed. Never retry it. */
            throw new SensorError(detail, res.status, res.status === 401);
          });
      },
      function (err) {
        throw new SensorError("could not reach Envelock — " + (err && err.message), 0);
      },
    );
  };

  /**
   * Trade a pairing code from the dashboard for this device's own token.
   * extra: anything the client wants remembered with the enrollment (e.g. the
   * webmail origin a browser extension should watch for this mailbox).
   */
  SensorClient.prototype.enroll = function (code, opts) {
    var self = this;
    opts = opts || {};
    var apiBase = String(opts.apiBase || this.apiBase).replace(/\/+$/, "");
    var device = describeDevice(this.userAgent, opts.appName);
    return this.deviceId().then(function (deviceId) {
      return self
        ._request(apiBase + "/api/v1/sensor/enroll", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            code: String(code || "").trim(),
            client: self.client,
            device_fingerprint: deviceId,
            label: opts.label || device.label,
          }),
        })
        .then(function (body) {
          var enrollment = Object.assign({}, opts.extra || {}, {
            mailbox: normalizeMailbox(body.mailbox),
            token: body.token,
            deviceId: deviceId,
            apiBase: apiBase,
            client: self.client,
            label: opts.label || device.label,
            enrolledAt: new Date(self.now()).toISOString(),
            lastBeatAt: null,
            lastError: null,
            revoked: false,
          });
          return self.enrollments().then(function (list) {
            /* Re-pairing the same mailbox replaces the old token. */
            var rest = list.filter(function (e) {
              return e.mailbox !== enrollment.mailbox;
            });
            rest.push(enrollment);
            return self._save(rest).then(function () {
              return enrollment;
            });
          });
        });
    });
  };

  SensorClient.prototype.remove = function (mailbox) {
    var self = this;
    var key = normalizeMailbox(mailbox);
    return this.enrollments().then(function (list) {
      return self._save(
        list.filter(function (e) {
          return e.mailbox !== key;
        }),
      );
    });
  };

  SensorClient.prototype._post = function (enrollment, path, body) {
    var self = this;
    return this._request(enrollment.apiBase + path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Sensor " + enrollment.token,
      },
      body: JSON.stringify(body),
    }).catch(function (err) {
      var patch = { lastError: err.message };
      if (err.revoked) patch.revoked = true;
      return self._update(enrollment.mailbox, patch).then(function () {
        throw err;
      });
    });
  };

  function active(list, mailboxes) {
    var only = mailboxes
      ? mailboxes.map(normalizeMailbox)
      : null;
    return list.filter(function (e) {
      return !e.revoked && (!only || only.indexOf(e.mailbox) !== -1);
    });
  }

  /**
   * "This device is here", for the given mailboxes (default: every live
   * enrollment). A client calls this on a timer, but only while the mail
   * client that reads the mailbox is actually open — presence is the point.
   * Resolves to one result per mailbox; never rejects.
   */
  SensorClient.prototype.heartbeat = function (opts) {
    var self = this;
    opts = opts || {};
    var device = describeDevice(this.userAgent, opts.appName);
    return Promise.all([this.enrollments(), this.deviceId()]).then(function (both) {
      var targets = active(both[0], opts.mailboxes);
      return Promise.all(
        targets.map(function (e) {
          return self
            ._post(e, "/api/v1/sensor/heartbeat", {
              device_fingerprint: both[1],
              os: device.os,
              browser: opts.browser || (self.client === "browser" ? device.app : null),
              mail_client: opts.mailClient || null,
            })
            .then(function (body) {
              return self
                ._update(e.mailbox, {
                  lastBeatAt: new Date(self.now()).toISOString(),
                  lastError: null,
                })
                .then(function () {
                  return { mailbox: e.mailbox, ok: true, body: body };
                });
            })
            .catch(function (err) {
              return { mailbox: e.mailbox, ok: false, error: err.message, revoked: err.revoked };
            });
        }),
      ).then(function (results) {
        return self._flushPending().then(function () {
          return results;
        });
      });
    });
  };

  /**
   * "The owner opened this message." messageRef is the Message-ID header when
   * the client can see it, or ACTIVITY_REF when it can only tell the owner is
   * reading. A send that fails is kept and retried with the next heartbeat —
   * unless it has aged past what the server would still accept.
   */
  SensorClient.prototype.attest = function (mailbox, messageRef) {
    var self = this;
    var key = normalizeMailbox(mailbox);
    var ref = normalizeMessageRef(messageRef || ACTIVITY_REF) || ACTIVITY_REF;
    var at = this.now();
    return Promise.all([this.enrollments(), this.deviceId()]).then(function (both) {
      var e = active(both[0], [key])[0];
      if (!e) return { ok: false, error: "not enrolled for " + key };
      return self
        ._post(e, "/api/v1/sensor/message-opened", {
          device_fingerprint: both[1],
          message_ref: ref,
        })
        .then(function (body) {
          return { ok: true, body: body };
        })
        .catch(function (err) {
          if (!err.revoked && err.status !== 403) {
            self.pending.push({ mailbox: key, ref: ref, at: at });
            if (self.pending.length > 50) self.pending.shift();
          }
          return { ok: false, error: err.message };
        });
    });
  };

  SensorClient.prototype._flushPending = function () {
    var self = this;
    var cutoff = this.now() - ATTEST_MAX_AGE_MS;
    var due = this.pending.filter(function (p) {
      return p.at >= cutoff;
    });
    this.pending = [];
    return Promise.all(
      due.map(function (p) {
        return self.attest(p.mailbox, p.ref);
      }),
    );
  };

  /**
   * One snapshot for a status screen. `live` means a heartbeat landed within
   * the window the server itself uses to decide a session has ended.
   */
  SensorClient.prototype.status = function () {
    var self = this;
    return this.enrollments().then(function (list) {
      var now = self.now();
      return list.map(function (e) {
        var last = e.lastBeatAt ? Date.parse(e.lastBeatAt) : 0;
        return {
          mailbox: e.mailbox,
          label: e.label,
          client: e.client,
          lastBeatAt: e.lastBeatAt,
          lastError: e.lastError,
          revoked: Boolean(e.revoked),
          live: !e.revoked && Boolean(last) && now - last <= 180 * 1000,
        };
      });
    });
  };

  /**
   * The server's warning for a message the person just opened, as one line of
   * at most 150 characters — Outlook's notification bar limit, and about what
   * a toolbar tooltip or desktop notification shows. Null when there is none.
   */
  function warningLine(warning) {
    if (!warning || !warning.action) return null;
    var label = warning.confirmed_fraud
      ? "Envelock: confirmed fraud."
      : "Envelock " + String(warning.tier || "").toUpperCase() + ":";
    var line = label + " " + warning.action;
    return line.length > 150 ? line.slice(0, 147) + "..." : line;
  }

  /** The warning in an attest() result, if the server sent one. */
  function warningOf(result) {
    return (result && result.ok && result.body && result.body.warning) || null;
  }

  root.EnvelockSensor = {
    warningLine: warningLine,
    warningOf: warningOf,
    DEFAULT_API_BASE: DEFAULT_API_BASE,
    ACTIVITY_REF: ACTIVITY_REF,
    HEARTBEAT_SECONDS: HEARTBEAT_SECONDS,
    ATTEST_MAX_AGE_MS: ATTEST_MAX_AGE_MS,
    normalizeMessageRef: normalizeMessageRef,
    normalizeMailbox: normalizeMailbox,
    newDeviceId: newDeviceId,
    describeDevice: describeDevice,
    memoryStorage: memoryStorage,
    extensionStorage: extensionStorage,
    webStorage: webStorage,
    SensorClient: SensorClient,
    SensorError: SensorError,
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
