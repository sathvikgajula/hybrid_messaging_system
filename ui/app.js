const $ = (id) => document.getElementById(id);
let iceServers = [];

function api() {
  if (window.pywebview && window.pywebview.api) return window.pywebview.api;
  return null;
}

function waitApi() {
  return new Promise((resolve) => {
    if (api()) return resolve(api());
    window.addEventListener("pywebviewready", () => resolve(api()), { once: true });
    const t = setInterval(() => {
      if (api()) {
        clearInterval(t);
        resolve(api());
      }
    }, 50);
  });
}

function showBusy(text) {
  $("busy-text").textContent = text || "Working…";
  $("busy").classList.remove("hidden");
}
function hideBusy() {
  $("busy").classList.add("hidden");
}

function setAuthError(msg) {
  $("auth-error").textContent = msg || "";
}

function escapeText(node, text) {
  node.textContent = text == null ? "" : String(text);
}

function renderSnapshot(snap) {
  if (!snap || !snap.authed) {
    $("auth").classList.remove("hidden");
    $("app").classList.add("hidden");
    return;
  }
  $("auth").classList.add("hidden");
  $("app").classList.remove("hidden");
  if (Array.isArray(snap.ice_servers)) iceServers = snap.ice_servers;
  escapeText($("me-name"), "@" + snap.username);
  escapeText($("me-fp"), snap.fingerprint || "");
  const pill = $("presence");
  pill.textContent = snap.online ? "sealed · online" : "offline";
  pill.classList.toggle("off", !snap.online);

  const list = $("chat-list");
  list.replaceChildren();
  (snap.chats || []).forEach((c) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "chat-item" + (snap.active && snap.active.id === c.id ? " on" : "");
    const t = document.createElement("div");
    t.className = "t";
    t.textContent = c.type === "group" ? c.title : "@" + c.title;
    const p = document.createElement("div");
    p.className = "p";
    p.textContent = c.preview || (c.type === "group" ? "Encrypted group" : "Safety number " + (c.fingerprint || ""));
    btn.append(t, p);
    btn.addEventListener("click", async () => {
      await api().open_chat(c.id);
      refresh();
    });
    list.append(btn);
  });

  const title = $("thread-title");
  const sub = $("thread-sub");
  const box = $("messages");
  box.replaceChildren();
  if (!snap.active) {
    title.textContent = "Select a chat";
    sub.textContent = "Find someone by username. Keys are verified before you send.";
    $("btn-call").classList.add("hidden");
    renderCallChrome(snap.call);
    return;
  }
  const a = snap.active;
  title.textContent = a.type === "group" ? a.title : "@" + a.title;
  if (a.type === "group") {
    sub.textContent = (a.members || []).map((m) => "@" + m).join(" · ") + " · hidden from the relay";
  } else {
    sub.textContent = "Safety number " + (a.fingerprint || "") + " · " + (a.members || []).length + " of you";
  }
  $("btn-call").classList.toggle("hidden", a.type !== "dm");
  (a.messages || []).forEach((m) => {
    const el = document.createElement("div");
    el.className = "bubble " + (m.mine ? "me" : "them");
    if (m.file) {
      const row = document.createElement("div");
      row.className = "file-row";
      const label = document.createElement("span");
      label.textContent = "📎 " + m.file.name + " · " + (m.file.size || 0) + " bytes";
      const save = document.createElement("button");
      save.type = "button";
      save.className = "ghost";
      save.textContent = "Save";
      save.addEventListener("click", () => saveAttachment(m.file.sha256));
      row.append(label, save);
      el.append(row);
    } else {
      el.append(document.createTextNode(m.text || ""));
    }
    const meta = document.createElement("span");
    meta.className = "meta";
    const when = m.ts ? new Date(m.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
    meta.textContent = (m.mine ? "you" : "@" + m.from) + " · " + (m.scheme || "") + (when ? " · " + when : "");
    el.append(meta);
    box.append(el);
  });
  box.scrollTop = box.scrollHeight;
  renderCallChrome(snap.call);
}

async function refresh() {
  const snap = await api().snapshot();
  renderSnapshot(snap);
}

async function boot() {
  const bridge = await waitApi();
  $("tab-login").onclick = () => {
    $("tab-login").classList.add("on");
    $("tab-signup").classList.remove("on");
    $("form-login").classList.remove("hidden");
    $("form-signup").classList.add("hidden");
  };
  $("tab-signup").onclick = () => {
    $("tab-signup").classList.add("on");
    $("tab-login").classList.remove("on");
    $("form-signup").classList.remove("hidden");
    $("form-login").classList.add("hidden");
  };

  $("form-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    setAuthError("");
    showBusy("Unlocking keys…");
    const res = await bridge.login($("login-user").value, $("login-pass").value);
    hideBusy();
    if (!res.ok) return setAuthError(res.error);
    await refresh();
  });

    $("form-signup").addEventListener("submit", async (e) => {
    e.preventDefault();
    setAuthError("");
    showBusy("Generating keys…");
    const res = await bridge.signup(
      $("signup-user").value,
      $("signup-pass").value,
      $("signup-pass2").value,
      $("signup-invite").value
    );
    if (!res.ok) {
      hideBusy();
      return setAuthError(res.error);
    }
    if (res.pending) {
      while (true) {
        await new Promise((r) => setTimeout(r, 350));
        const job = await bridge.job_status();
        if (job && job.message) showBusy(job.message);
        if (job && job.status === "done") {
          hideBusy();
          await refresh();
          return;
        }
        if (job && job.status === "error") {
          hideBusy();
          setAuthError(job.error || "Signup failed");
          return;
        }
      }
    }
    hideBusy();
    await refresh();
  });

  $("btn-dm").addEventListener("click", async () => {
    const name = $("find-user").value;
    showBusy("Verifying identity…");
    const res = await bridge.start_dm(name);
    hideBusy();
    if (!res.ok) {
      alert(res.error);
      return;
    }
    $("find-user").value = "";
    await refresh();
  });

  $("btn-group").addEventListener("click", () => $("modal").classList.remove("hidden"));
  $("group-cancel").addEventListener("click", () => $("modal").classList.add("hidden"));
  $("group-create").addEventListener("click", async () => {
    $("group-error").textContent = "";
    showBusy("Sealing invites…");
    const res = await bridge.create_group($("group-title").value, $("group-people").value);
    hideBusy();
    if (!res.ok) {
      $("group-error").textContent = res.error;
      return;
    }
    $("modal").classList.add("hidden");
    $("group-title").value = "";
    $("group-people").value = "";
    await refresh();
  });

  $("composer").addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = $("draft").value;
    const res = await bridge.send(text, "rsa");
    if (!res.ok) {
      alert(res.error);
      return;
    }
    $("draft").value = "";
    await refresh();
  });

  $("btn-attach").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", async () => {
    const file = $("file-input").files && $("file-input").files[0];
    $("file-input").value = "";
    if (!file) return;
    const snap = await api().snapshot();
    if (snap.max_file_bytes && file.size > snap.max_file_bytes) {
      alert("Attachment too large (max 2 MB)");
      return;
    }
    showBusy("Sealing attachment…");
    try {
      const data = await readFileB64(file);
      const res = await api().send_file(file.name, data, file.type || "application/octet-stream", "rsa");
      hideBusy();
      if (!res.ok) alert(res.error);
      else await refresh();
    } catch (err) {
      hideBusy();
      alert(String(err));
    }
  });

  $("btn-call").addEventListener("click", () => startCall());
  $("btn-hangup").addEventListener("click", () => hangup(true));
  $("btn-accept").addEventListener("click", () => acceptCall());
  $("btn-reject").addEventListener("click", () => rejectCall());

  setInterval(async () => {
    if (!api()) return;
    const events = await api().poll();
    let needRefresh = false;
    for (const ev of events || []) {
      if (ev.type === "call") await onCallEvent(ev);
      else needRefresh = true;
    }
    if (needRefresh || (events && events.length)) await refresh();
  }, 400);
}

let pc = null;
let localStream = null;
let callState = null;

function renderCallChrome(call) {
  const bar = $("call-bar");
  const incoming = $("incoming");
  if (call && (call.status === "calling" || call.status === "live")) {
    bar.classList.remove("hidden");
    $("call-status").textContent =
      call.status === "live" ? "Sealed voice call with @" + call.peer : "Calling @" + call.peer + "…";
  } else if (callState && (callState.status === "calling" || callState.status === "live")) {
    bar.classList.remove("hidden");
    $("call-status").textContent =
      callState.status === "live" ? "Sealed voice call with @" + callState.peer : "Calling @" + callState.peer + "…";
  } else {
    bar.classList.add("hidden");
  }
  if (call && call.status === "ringing" && call.role === "callee") {
    incoming.classList.remove("hidden");
    $("incoming-from").textContent = "@" + call.peer + " is calling. Media is peer-to-peer; the relay only sees a sealed signal.";
  } else if (callState && callState.status === "ringing") {
    incoming.classList.remove("hidden");
    $("incoming-from").textContent = "@" + callState.peer + " is calling. Media is peer-to-peer; the relay only sees a sealed signal.";
  } else {
    incoming.classList.add("hidden");
  }
}

function readFileB64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Could not read file"));
    reader.onload = () => {
      const result = String(reader.result || "");
      const comma = result.indexOf(",");
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.readAsDataURL(file);
  });
}

async function saveAttachment(digest) {
  showBusy("Unlocking attachment…");
  const res = await api().export_file(digest);
  hideBusy();
  if (!res.ok) {
    alert(res.error);
    return;
  }
  const bin = atob(res.data);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = res.name || "attachment";
  a.click();
  URL.revokeObjectURL(url);
}

async function getMic() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error("This window cannot access the microphone");
  }
  return navigator.mediaDevices.getUserMedia({
    audio: { echoCancellation: true, noiseSuppression: true },
    video: false,
  });
}

function closeMedia() {
  if (localStream) {
    localStream.getTracks().forEach((t) => t.stop());
    localStream = null;
  }
  if (pc) {
    pc.onicecandidate = null;
    pc.ontrack = null;
    pc.close();
    pc = null;
  }
  $("remote-audio").srcObject = null;
}

let iceQueue = [];

function flushIce() {
  if (!callState) return;
  iceQueue.forEach((cand) => api().call_signal("ice", callState.id, null, cand));
  iceQueue = [];
}

function wirePeer(peerName) {
  iceQueue = [];
  pc = new RTCPeerConnection({ iceServers: iceServers });
  localStream.getTracks().forEach((t) => pc.addTrack(t, localStream));
  pc.onicecandidate = (e) => {
    if (!e.candidate) return;
    const cand = e.candidate.toJSON();
    if (!callState) {
      iceQueue.push(cand);
      return;
    }
    api().call_signal("ice", callState.id, null, cand);
  };
  pc.ontrack = (e) => {
    const audio = $("remote-audio");
    audio.srcObject = e.streams[0];
    audio.play().catch(() => {});
  };
  pc.onconnectionstatechange = () => {
    if (!pc) return;
    if (pc.connectionState === "connected" && callState) {
      callState.status = "live";
      renderCallChrome({ status: "live", peer: peerName || callState.peer });
    }
    if (pc.connectionState === "failed") {
      if (callState) hangup(true);
    }
  };
}

async function startCall() {
  try {
    const snap = await api().snapshot();
    if (!snap.active || !snap.active.can_call) {
      alert("Voice calls are 1:1 only. Open a direct chat first.");
      return;
    }
    if (snap.call) {
      alert("Already in a call");
      return;
    }
    localStream = await getMic();
    wirePeer();
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    const res = await api().call_start(pc.localDescription.sdp);
    if (!res.ok) {
      closeMedia();
      alert(res.error);
      return;
    }
    callState = { id: res.call_id, peer: res.peer, role: "caller", status: "calling" };
    flushIce();
    renderCallChrome(callState);
  } catch (err) {
    closeMedia();
    alert(err && err.message ? err.message : String(err));
  }
}

async function acceptCall() {
  if (!callState || !callState.sdp) {
    const snap = await api().snapshot();
    if (!snap.call || snap.call.status !== "ringing" || !snap.call.sdp) return;
    callState = {
      id: snap.call.id,
      peer: snap.call.peer,
      role: "callee",
      status: "ringing",
      sdp: snap.call.sdp,
      pendingIce: (callState && callState.pendingIce) || [],
    };
  }
  try {
    localStream = await getMic();
    wirePeer(callState && callState.peer);
    await pc.setRemoteDescription({ type: "offer", sdp: callState.sdp });
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    const res = await api().call_signal("answer", callState.id, pc.localDescription.sdp, null);
    if (!res.ok) {
      closeMedia();
      alert(res.error);
      return;
    }
    for (const cand of callState.pendingIce || []) {
      try {
        await pc.addIceCandidate(cand);
      } catch (_e) {
        /* ignore stale candidates */
      }
    }
    callState.status = "live";
    callState.pendingIce = [];
    $("incoming").classList.add("hidden");
    renderCallChrome(callState);
  } catch (err) {
    closeMedia();
    alert(err && err.message ? err.message : String(err));
  }
}

async function rejectCall() {
  let id = callState && callState.id;
  if (!id) {
    const snap = await api().snapshot();
    if (snap.call && snap.call.id) id = snap.call.id;
  }
  if (id) await api().call_signal("reject", id, null, null);
  closeMedia();
  callState = null;
  $("incoming").classList.add("hidden");
  renderCallChrome(null);
}

async function hangup(notify) {
  if (notify && callState) {
    try {
      await api().call_hangup();
    } catch (_e) {
      /* ignore */
    }
  }
  closeMedia();
  callState = null;
  renderCallChrome(null);
}

async function onCallEvent(ev) {
  if (ev.event === "offer") {
    if (callState && (callState.status === "calling" || callState.status === "live")) return;
    closeMedia();
    callState = {
      id: ev.call_id,
      peer: ev.from,
      role: "callee",
      status: "ringing",
      sdp: ev.sdp,
      pendingIce: [],
    };
    renderCallChrome(callState);
    return;
  }
  if (!callState || ev.call_id !== callState.id) return;
  if (ev.event === "answer" && pc) {
    try {
      await pc.setRemoteDescription({ type: "answer", sdp: ev.sdp });
    } catch (_e) {
      hangup(true);
      alert("Call failed (bad answer).");
      return;
    }
    callState.status = "live";
    renderCallChrome(callState);
    return;
  }
  if (ev.event === "ice" && ev.candidate) {
    if (pc && pc.remoteDescription) {
      try {
        await pc.addIceCandidate(ev.candidate);
      } catch (_e) {
        /* ignore */
      }
    } else {
      callState.pendingIce = callState.pendingIce || [];
      callState.pendingIce.push(ev.candidate);
    }
    return;
  }
  if (ev.event === "hangup" || ev.event === "reject") {
    closeMedia();
    callState = null;
    renderCallChrome(null);
  }
}
