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
    sub.textContent = "Find a friend by username, then Chat or Call. Voice is 1:1 only.";
    $("btn-call").classList.add("hidden");
    $("btn-invite").classList.add("hidden");
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
  $("btn-invite").classList.toggle("hidden", !a.can_invite);
  (a.messages || []).forEach((m) => {
    const el = document.createElement("div");
    el.className = "bubble " + (m.mine ? "me" : "them");
    if (m.file) {
      const row = document.createElement("div");
      row.className = "file-row";
      const label = document.createElement("span");
      label.textContent = "📎 " + m.file.name + " · " + sizeLabel(m.file.size);
      const save = document.createElement("button");
      save.type = "button";
      save.className = "ghost";
      save.textContent = "Save as…";
      save.addEventListener("click", () => saveAttachment(m.file.sha256));
      const copy = document.createElement("button");
      copy.type = "button";
      copy.className = "ghost";
      copy.textContent = "Copy";
      copy.addEventListener("click", () => copyAttachment(m.file));
      row.append(label, save, copy);
      el.append(row);
      if (looksLikeImage(m.file)) {
        const img = document.createElement("img");
        img.className = "thumb";
        img.alt = m.file.name;
        img.addEventListener("error", () => img.remove());
        loadPreview(m.file, img);
        el.append(img);
      }
    } else if (m.xftp) {
      const row = document.createElement("div");
      row.className = "file-row";
      const label = document.createElement("span");
      label.textContent = "📦 " + m.xftp.name + " · " + sizeLabel(m.xftp.size) + " · large file";
      const save = document.createElement("button");
      save.type = "button";
      save.className = "ghost";
      save.textContent = "Save as…";
      save.addEventListener("click", () => downloadXftp(m.xftp.file_id));
      row.append(label, save);
      el.append(row);
    } else {
      el.append(document.createTextNode(m.text || ""));
      const copyTxt = document.createElement("button");
      copyTxt.type = "button";
      copyTxt.className = "ghost copy-txt";
      copyTxt.textContent = "Copy";
      copyTxt.addEventListener("click", () => copyText(m.text || ""));
      el.append(copyTxt);
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

function showLogin() {
  $("tab-login").classList.add("on");
  $("tab-signup").classList.remove("on");
  $("form-login").classList.remove("hidden");
  $("form-signup").classList.add("hidden");
}

function showSignup() {
  $("tab-signup").classList.add("on");
  $("tab-login").classList.remove("on");
  $("form-signup").classList.remove("hidden");
  $("form-login").classList.add("hidden");
}

$("tab-login").addEventListener("click", showLogin);
$("tab-signup").addEventListener("click", showSignup);
$("form-login").addEventListener("submit", (e) => e.preventDefault());
$("form-signup").addEventListener("submit", (e) => e.preventDefault());

let groupModalMode = "create";

function openGroupModal(mode) {
  groupModalMode = mode === "invite" ? "invite" : "create";
  $("group-error").textContent = "";
  if (groupModalMode === "invite") {
    $("group-modal-title").textContent = "Invite to group";
    $("group-title-row").classList.add("hidden");
    $("group-create").textContent = "Invite";
  } else {
    $("group-modal-title").textContent = "New group";
    $("group-title-row").classList.remove("hidden");
    $("group-create").textContent = "Create";
  }
  $("modal").classList.remove("hidden");
}

async function boot() {
  const bridge = await waitApi();

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
      $("signup-pass2").value
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

  $("btn-find-call").addEventListener("click", async () => {
    const name = $("find-user").value;
    showBusy("Opening a sealed call…");
    const res = await bridge.start_dm(name);
    hideBusy();
    if (!res.ok) {
      alert(res.error);
      return;
    }
    $("find-user").value = "";
    await refresh();
    await startCall();
  });

  $("btn-group").addEventListener("click", () => openGroupModal("create"));
  $("btn-invite").addEventListener("click", () => openGroupModal("invite"));
  $("group-cancel").addEventListener("click", () => $("modal").classList.add("hidden"));
  $("group-create").addEventListener("click", async () => {
    $("group-error").textContent = "";
    const people = $("group-people").value;
    showBusy("Sealing invites…");
    const res = groupModalMode === "invite"
      ? await bridge.invite_to_group(people)
      : await bridge.create_group($("group-title").value, people);
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
    const files = Array.from(($("file-input").files || []));
    $("file-input").value = "";
    for (const file of files) {
      await sendLocalFile(file);
    }
  });
  wirePasteAndDrop();

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

function looksLikeImage(file) {
  const mime = (file && file.mime) || "";
  const name = (file && file.name) || "";
  return mime.startsWith("image/") || /\.(png|jpe?g|gif|webp|bmp)$/i.test(name);
}

const previewCache = {};

async function loadPreview(file, img) {
  const digest = file.sha256;
  if (previewCache[digest]) {
    img.src = previewCache[digest];
    return;
  }
  try {
    const res = await api().export_file(digest);
    if (!res.ok) return;
    const mime = res.mime && res.mime.startsWith("image/") ? res.mime : "image/png";
    const url = "data:" + mime + ";base64," + res.data;
    previewCache[digest] = url;
    img.src = url;
  } catch (_e) {
    /* ignore */
  }
}

function sizeLabel(n) {
  if (!n) return "";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return Math.round(n / 1024) + " KB";
  if (n < 1024 * 1024 * 1024) {
    const mb = n / (1024 * 1024);
    return (Math.abs(mb - Math.round(mb)) < 0.05 ? Math.round(mb) : mb.toFixed(1)) + " MB";
  }
  const gb = n / (1024 * 1024 * 1024);
  return (Math.abs(gb - Math.round(gb)) < 0.05 ? Math.round(gb) : gb.toFixed(1)) + " GB";
}

async function sendLocalFile(file) {
  if (!file) return;
  const snap = await api().snapshot();
  if (!snap.authed || !snap.active) {
    alert("Open a chat first, then drop or paste the file.");
    return;
  }
  const maxInline = snap.max_file_bytes || 0;
  const maxLarge = snap.max_xftp_bytes || 0;
  if (maxLarge && file.size > maxLarge) {
    alert("Attachment too large (max " + sizeLabel(maxLarge) + ")");
    return;
  }
  if (maxInline && file.size > maxInline) {
    await sendXftpFile(file, snap);
    return;
  }
  showBusy("Sealing attachment…");
  try {
    const data = await readFileB64(file);
    const res = await api().send_file(file.name || "attachment", data, file.type || "application/octet-stream", "rsa");
    hideBusy();
    if (!res.ok) alert(res.error);
    else await refresh();
  } catch (err) {
    hideBusy();
    alert(String(err));
  }
}

async function sendXftpFile(file, snap) {
  showBusy("Preparing large file…");
  try {
    const begin = await api().xftp_begin(file.name || "attachment", file.size, file.type || "application/octet-stream");
    if (!begin.ok) {
      hideBusy();
      alert(begin.error);
      return;
    }
    const slice = begin.slice || 262144;
    let offset = 0;
    while (offset < file.size) {
      const end = Math.min(offset + slice, file.size);
      const data = await readFileB64(file.slice(offset, end));
      const res = await api().xftp_push(begin.id, data);
      if (!res.ok) {
        hideBusy();
        alert(res.error);
        return;
      }
      offset = end;
      showBusy("Uploading sealed chunks… " + (res.pct || Math.round(100 * offset / file.size)) + "%");
    }
    showBusy("Sending file description…");
    const done = await api().xftp_finish(begin.id);
    hideBusy();
    if (!done.ok) alert(done.error);
    else await refresh();
  } catch (err) {
    hideBusy();
    alert(String(err));
  }
}

async function downloadXftp(fileId) {
  showBusy("Choose where to save, then downloading sealed chunks…");
  const res = await api().download_xftp(fileId);
  hideBusy();
  if (res.cancelled) return;
  if (!res.ok) {
    alert(res.error);
    return;
  }
  alert("Saved to:\n" + res.path + "\n\nFinder will highlight the file.");
}

function clipHasFiles(transfer) {
  if (!transfer) return false;
  const types = transfer.types ? Array.from(transfer.types) : [];
  return types.includes("Files") || types.includes("application/x-moz-file");
}

function filesFromClipboard(clip) {
  const files = Array.from((clip && clip.files) || []);
  if (files.length || !clip || !clip.items) return files;
  for (const item of clip.items) {
    if (item.kind === "file") {
      const f = item.getAsFile();
      if (f) files.push(f);
    }
  }
  return files;
}

function wirePasteAndDrop() {
  document.addEventListener("paste", async (e) => {
    if ($("app").classList.contains("hidden")) return;
    const clip = e.clipboardData;
    const files = filesFromClipboard(clip);
    if (files.length) {
      e.preventDefault();
      for (const file of files) await sendLocalFile(file);
      return;
    }
    const target = e.target;
    const inField = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA");
    if (inField) return;
    const text = clip ? clip.getData("text/plain") : "";
    if (!text) return;
    e.preventDefault();
    const draft = $("draft");
    draft.value = (draft.value || "") + text;
    draft.focus();
  });

  const hint = $("drop-hint");
  let dragDepth = 0;
  function showDrop(on) {
    if (hint) hint.classList.toggle("hidden", !on);
  }
  document.addEventListener("dragenter", (e) => {
    if (!clipHasFiles(e.dataTransfer)) return;
    e.preventDefault();
    if ($("app").classList.contains("hidden")) return;
    dragDepth += 1;
    showDrop(true);
  });
  document.addEventListener("dragover", (e) => {
    if (!clipHasFiles(e.dataTransfer)) return;
    e.preventDefault();
    try { e.dataTransfer.dropEffect = "copy"; } catch (_e) { /* ignore */ }
  });
  document.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) showDrop(false);
  });
  document.addEventListener("drop", async (e) => {
    dragDepth = 0;
    showDrop(false);
    const files = Array.from((e.dataTransfer && e.dataTransfer.files) || []);
    if (!files.length) return;
    e.preventDefault();
    if ($("app").classList.contains("hidden")) return;
    for (const file of files) await sendLocalFile(file);
  });
}

async function saveAttachment(digest) {
  showBusy("Choose where to save…");
  const res = await api().save_file(digest);
  hideBusy();
  if (res.cancelled) return;
  if (!res.ok) {
    alert(res.error);
    return;
  }
  alert("Saved to:\n" + res.path + "\n\nFinder will highlight the file.");
}

async function copyText(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
  } catch (_e) {
    /* fall through */
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  document.body.append(ta);
  ta.select();
  document.execCommand("copy");
  ta.remove();
}

async function copyAttachment(file) {
  showBusy("Copying…");
  try {
    if (looksLikeImage(file) && api().copy_file) {
      const native = await api().copy_file(file.sha256);
      hideBusy();
      if (native.ok) {
        alert("Image copied. Paste it into another app, or back into this chat.");
        return;
      }
    }
    const res = await api().export_file(file.sha256);
    hideBusy();
    if (!res.ok) {
      alert(res.error);
      return;
    }
    const mime = (res.mime && res.mime.startsWith("image/")) ? res.mime : null;
    if (mime && navigator.clipboard && navigator.clipboard.write && window.ClipboardItem) {
      const bin = atob(res.data);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
      await navigator.clipboard.write([new ClipboardItem({ [mime]: new Blob([bytes], { type: mime }) })]);
      alert("Image copied. Paste it anywhere.");
      return;
    }
    alert("Use Save as… to pick a folder, then copy the file from there.");
  } catch (err) {
    hideBusy();
    alert(String(err));
  }
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

boot();
