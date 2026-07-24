const { invoke } = window.__TAURI__.core;
const { getCurrentWebview } = window.__TAURI__.webview;

const el = (id) => document.getElementById(id);

const screenLock = el("screen-lock");
const screenMain = el("screen-main");
const vaultPathInput = el("vault-path");
const passphraseInput = el("passphrase");
const lockError = el("lock-error");
const btnUnlock = el("btn-unlock");
const btnCreate = el("btn-create");

const vaultPathLabel = el("vault-path-label");
const btnLock = el("btn-lock");
const btnSettings = el("btn-settings");
const dropzone = el("dropzone");
const searchInput = el("search");
const entryCount = el("entry-count");
const entriesBody = el("entries-body");
const emptyState = el("empty-state");
const toast = el("toast");
const advancedToggle = el("advanced-toggle");
const advancedPanel = el("advanced-panel");
const cipherSelect = el("cipher-select");

let homeDir = "";
let entriesCache = [];
let activeEntryIdForTags = null;
let activeEntryIdForExport = null;
let activeEntryNameForExport = null;
let autoLockTimer = null;

function showToast(message, isError = false) {
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.hidden = false;
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => {
    toast.hidden = true;
  }, 3500);
}

function errorMessage(err) {
  if (!err || typeof err !== "object") return String(err);
  switch (err.kind) {
    case "wrong_passphrase":
      return "Mot de passe incorrect.";
    case "tampered":
      return "Données altérées ou corrompues : échec de vérification d'intégrité.";
    case "not_found":
      return "Élément introuvable.";
    case "already_exists":
      return "Un coffre existe déjà à cet emplacement.";
    case "vault_not_found":
      return "Aucun coffre trouvé à cet emplacement.";
    case "locked":
      return "Le coffre est verrouillé.";
    case "too_large":
      return "Fichier trop volumineux pour cette opération.";
    case "wiped":
      return "Ce coffre a été détruit (seuil de tentatives échouées atteint).";
    case "unsupported":
      return err.message;
    default:
      return err.message || "Erreur inconnue.";
  }
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  const units = ["Ko", "Mo", "Go", "To"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

function formatDate(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

// ---------- Écran de verrouillage ----------

async function init() {
  try {
    homeDir = await invoke("home_dir");
    vaultPathInput.value = await invoke("default_vault_dir");
  } catch (e) {
    // pas bloquant
  }
}

advancedToggle.addEventListener("click", () => {
  const expanded = advancedToggle.getAttribute("aria-expanded") === "true";
  advancedToggle.setAttribute("aria-expanded", String(!expanded));
  advancedPanel.hidden = expanded;
});

function setLockError(msg) {
  if (!msg) {
    lockError.hidden = true;
    lockError.textContent = "";
  } else {
    lockError.hidden = false;
    lockError.textContent = msg;
  }
}

btnUnlock.addEventListener("click", async () => {
  setLockError(null);
  const path = vaultPathInput.value.trim();
  const passphrase = passphraseInput.value;
  if (!path || !passphrase) {
    setLockError("Renseignez l'emplacement du coffre et le mot de passe.");
    return;
  }
  btnUnlock.disabled = true;
  try {
    await invoke("unlock_vault", { path, passphrase });
    passphraseInput.value = "";
    await enterMain(path);
  } catch (e) {
    setLockError(errorMessage(e));
  } finally {
    btnUnlock.disabled = false;
  }
});

btnCreate.addEventListener("click", async () => {
  setLockError(null);
  const path = vaultPathInput.value.trim();
  const passphrase = passphraseInput.value;
  if (!path || !passphrase) {
    setLockError("Renseignez l'emplacement du coffre et le mot de passe.");
    return;
  }
  if (passphrase.length < 8) {
    setLockError("Choisissez un mot de passe d'au moins 8 caractères.");
    return;
  }
  btnCreate.disabled = true;
  try {
    await invoke("create_vault", { path, passphrase, cipher: cipherSelect.value });
    passphraseInput.value = "";
    await enterMain(path);
  } catch (e) {
    setLockError(errorMessage(e));
  } finally {
    btnCreate.disabled = false;
  }
});

// ---------- Écran principal ----------

async function enterMain(path) {
  screenLock.hidden = true;
  screenMain.hidden = false;
  vaultPathLabel.textContent = path;
  await refreshEntries();
  resetAutoLockTimer();
}

async function backToLock() {
  screenMain.hidden = true;
  screenLock.hidden = false;
  entriesCache = [];
  renderEntries();
  clearTimeout(autoLockTimer);
}

btnLock.addEventListener("click", async () => {
  try {
    await invoke("lock_vault");
  } catch (e) {
    // ignore
  }
  await backToLock();
});

// ---------- Verrouillage automatique ----------

function autoLockMinutes() {
  return parseInt(localStorage.getItem("autolock-minutes") ?? "5", 10);
}

function resetAutoLockTimer() {
  clearTimeout(autoLockTimer);
  if (screenMain.hidden) return;
  const minutes = autoLockMinutes();
  if (!minutes || minutes <= 0) return;
  autoLockTimer = setTimeout(async () => {
    try {
      await invoke("lock_vault");
    } catch (e) {
      // ignore
    }
    await backToLock();
    showToast("Coffre verrouillé automatiquement après inactivité.");
  }, minutes * 60 * 1000);
}

for (const evt of ["mousemove", "keydown", "click"]) {
  document.addEventListener(evt, () => resetAutoLockTimer(), { passive: true });
}

async function refreshEntries() {
  try {
    entriesCache = await invoke("list_entries");
    renderEntries();
  } catch (e) {
    showToast(errorMessage(e), true);
  }
}

function currentFilter() {
  return searchInput.value.trim().toLowerCase();
}

function renderEntries() {
  const filter = currentFilter();
  const filtered = entriesCache.filter((entry) => {
    if (!filter) return true;
    const haystack = (entry.original_name + " " + entry.tags.join(" ")).toLowerCase();
    return haystack.includes(filter);
  });

  entryCount.textContent = `${filtered.length} fichier${filtered.length > 1 ? "s" : ""}`;
  emptyState.hidden = entriesCache.length !== 0;
  entriesBody.innerHTML = "";

  for (const entry of filtered) {
    const tr = document.createElement("tr");

    const nameTd = document.createElement("td");
    nameTd.textContent = entry.original_name;
    nameTd.title = entry.original_name;
    tr.appendChild(nameTd);

    const sizeTd = document.createElement("td");
    sizeTd.textContent = formatSize(entry.size);
    tr.appendChild(sizeTd);

    const dateTd = document.createElement("td");
    dateTd.textContent = formatDate(entry.added_at);
    tr.appendChild(dateTd);

    const tagsTd = document.createElement("td");
    for (const tag of entry.tags) {
      const pill = document.createElement("span");
      pill.className = "tag-pill";
      pill.textContent = tag;
      tagsTd.appendChild(pill);
    }
    tr.appendChild(tagsTd);

    const actionsTd = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";

    if (entry.content_type && entry.content_type.startsWith("image/")) {
      const previewBtn = document.createElement("button");
      previewBtn.className = "ghost";
      previewBtn.textContent = "Aperçu";
      previewBtn.addEventListener("click", () => openPreview(entry.id));
      actions.appendChild(previewBtn);
    }

    const tagsBtn = document.createElement("button");
    tagsBtn.className = "ghost";
    tagsBtn.textContent = "Tags";
    tagsBtn.addEventListener("click", () => openTagsModal(entry));
    actions.appendChild(tagsBtn);

    const exportBtn = document.createElement("button");
    exportBtn.className = "secondary";
    exportBtn.textContent = "Exporter";
    exportBtn.addEventListener("click", () => openExportModal(entry));
    actions.appendChild(exportBtn);

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "danger-ghost";
    deleteBtn.textContent = "Supprimer";
    deleteBtn.addEventListener("click", () => deleteEntry(entry));
    actions.appendChild(deleteBtn);

    actionsTd.appendChild(actions);
    tr.appendChild(actionsTd);

    entriesBody.appendChild(tr);
  }
}

searchInput.addEventListener("input", renderEntries);

async function deleteEntry(entry) {
  const ok = confirm(`Supprimer définitivement « ${entry.original_name} » du coffre ?`);
  if (!ok) return;
  try {
    await invoke("delete_entry", { id: entry.id });
    showToast("Fichier supprimé.");
    await refreshEntries();
  } catch (e) {
    showToast(errorMessage(e), true);
  }
}

// ---------- Glisser-déposer ----------

async function addFiles(paths) {
  if (!paths || paths.length === 0) return;
  try {
    const added = await invoke("add_files", { paths, tags: [] });
    const n = added.length;
    showToast(`${n} fichier${n > 1 ? "s" : ""} chiffré${n > 1 ? "s" : ""} et ajouté${n > 1 ? "s" : ""} au coffre.`);
    await refreshEntries();
  } catch (e) {
    showToast(errorMessage(e), true);
  }
}

getCurrentWebview()
  .onDragDropEvent((event) => {
    const p = event.payload;
    if (p.type === "over") {
      dropzone.classList.add("dragover");
    } else if (p.type === "drop") {
      dropzone.classList.remove("dragover");
      addFiles(p.paths);
    } else {
      // "leave" (ou tout autre cas) : annule l'état visuel de survol.
      dropzone.classList.remove("dragover");
    }
  })
  .catch((e) => {
    showToast("Glisser-déposer indisponible : " + errorMessage(e), true);
  });

// ---------- Modale : tags ----------

const modalTags = el("modal-tags");
const tagsInput = el("tags-input");

function openTagsModal(entry) {
  activeEntryIdForTags = entry.id;
  tagsInput.value = entry.tags.join(", ");
  modalTags.hidden = false;
}

el("tags-cancel").addEventListener("click", () => {
  modalTags.hidden = true;
});

el("tags-confirm").addEventListener("click", async () => {
  const tags = tagsInput.value
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
  try {
    await invoke("set_tags", { id: activeEntryIdForTags, tags });
    modalTags.hidden = true;
    await refreshEntries();
  } catch (e) {
    showToast(errorMessage(e), true);
  }
});

// ---------- Modale : export ----------

const modalExport = el("modal-export");
const exportPathInput = el("export-path");
const exportError = el("export-error");

function openExportModal(entry) {
  activeEntryIdForExport = entry.id;
  activeEntryNameForExport = entry.original_name;
  exportPathInput.value = `${homeDir}/Downloads/${entry.original_name}`;
  exportError.hidden = true;
  modalExport.hidden = false;
}

el("export-cancel").addEventListener("click", () => {
  modalExport.hidden = true;
});

el("export-confirm").addEventListener("click", async () => {
  const dest = exportPathInput.value.trim();
  if (!dest) return;
  try {
    await invoke("export_file", { id: activeEntryIdForExport, dest });
    modalExport.hidden = true;
    showToast(`« ${activeEntryNameForExport} » déchiffré vers ${dest}`);
  } catch (e) {
    exportError.hidden = false;
    exportError.textContent = errorMessage(e);
  }
});

// ---------- Modale : aperçu ----------

const modalPreview = el("modal-preview");
const previewImg = el("preview-img");

async function openPreview(id) {
  try {
    const { content_type, data_base64 } = await invoke("get_preview", { id });
    previewImg.src = `data:${content_type};base64,${data_base64}`;
    modalPreview.hidden = false;
  } catch (e) {
    showToast(errorMessage(e), true);
  }
}

el("preview-close").addEventListener("click", () => {
  modalPreview.hidden = true;
  previewImg.src = "";
});

// ---------- Modale : réglages ----------

const modalSettings = el("modal-settings");
const autolockSelect = el("autolock-select");

async function refreshSettingsInfo() {
  const info = await invoke("vault_info");
  el("info-cipher").textContent = info.cipher_label;
  el("info-kdf").textContent = `Argon2id — ${info.kdf_memory_mib.toFixed(0)} Mio, ${info.kdf_iterations} itérations`;
  el("info-created").textContent = formatDate(info.created_at);
  el("info-count").textContent = `${info.entry_count}`;
  el("info-duress").textContent = info.duress_configured ? "Configuré" : "Non configuré";
  el("info-autowipe").textContent = info.auto_wipe_after
    ? `Après ${info.auto_wipe_after} échecs`
    : "Désactivée";
  return info;
}

btnSettings.addEventListener("click", async () => {
  autolockSelect.value = String(autoLockMinutes());
  try {
    await refreshSettingsInfo();
  } catch (e) {
    showToast(errorMessage(e), true);
  }
  modalSettings.hidden = false;
});

el("settings-close").addEventListener("click", () => {
  modalSettings.hidden = true;
});

autolockSelect.addEventListener("change", () => {
  localStorage.setItem("autolock-minutes", autolockSelect.value);
  resetAutoLockTimer();
});

el("btn-open-change-pw").addEventListener("click", () => {
  modalSettings.hidden = true;
  pwOld.value = "";
  pwNew.value = "";
  pwNew2.value = "";
  pwError.hidden = true;
  modalChangePw.hidden = false;
});

// ---------- Modale : changer le mot de passe ----------

const modalChangePw = el("modal-change-pw");
const pwOld = el("pw-old");
const pwNew = el("pw-new");
const pwNew2 = el("pw-new2");
const pwError = el("pw-error");

el("pw-cancel").addEventListener("click", () => {
  modalChangePw.hidden = true;
});

el("pw-confirm").addEventListener("click", async () => {
  pwError.hidden = true;
  if (pwNew.value.length < 8) {
    pwError.hidden = false;
    pwError.textContent = "Le nouveau mot de passe doit faire au moins 8 caractères.";
    return;
  }
  if (pwNew.value !== pwNew2.value) {
    pwError.hidden = false;
    pwError.textContent = "Les deux saisies du nouveau mot de passe ne correspondent pas.";
    return;
  }
  try {
    await invoke("change_passphrase", { old: pwOld.value, new: pwNew.value });
    modalChangePw.hidden = true;
    showToast("Mot de passe modifié.");
  } catch (e) {
    pwError.hidden = false;
    pwError.textContent = errorMessage(e);
  }
});

// ---------- AtomasDestruct : mot de passe de contrainte ----------

const modalDuress = el("modal-duress");
const duressDecoyPath = el("duress-decoy-path");
const duressPassphrase = el("duress-passphrase");
const duressPassphrase2 = el("duress-passphrase2");
const duressError = el("duress-error");

el("btn-open-duress").addEventListener("click", () => {
  modalSettings.hidden = true;
  duressDecoyPath.value = `${homeDir}/Kryptorium-Leurre`;
  duressPassphrase.value = "";
  duressPassphrase2.value = "";
  duressError.hidden = true;
  modalDuress.hidden = false;
});

el("duress-cancel").addEventListener("click", () => {
  modalDuress.hidden = true;
  modalSettings.hidden = false;
});

el("duress-clear").addEventListener("click", async () => {
  try {
    await invoke("clear_duress");
    modalDuress.hidden = true;
    modalSettings.hidden = false;
    await refreshSettingsInfo();
    showToast("Mot de passe de contrainte désactivé.");
  } catch (e) {
    duressError.hidden = false;
    duressError.textContent = errorMessage(e);
  }
});

el("duress-confirm").addEventListener("click", async () => {
  duressError.hidden = true;
  const decoyPath = duressDecoyPath.value.trim();
  const passphrase = duressPassphrase.value;

  if (!decoyPath || !passphrase) {
    duressError.hidden = false;
    duressError.textContent = "Renseignez l'emplacement du coffre-leurre et le mot de passe de contrainte.";
    return;
  }
  if (passphrase.length < 8) {
    duressError.hidden = false;
    duressError.textContent = "Le mot de passe de contrainte doit faire au moins 8 caractères.";
    return;
  }
  if (passphrase !== duressPassphrase2.value) {
    duressError.hidden = false;
    duressError.textContent = "Les deux saisies ne correspondent pas.";
    return;
  }

  try {
    const exists = await invoke("vault_exists", { path: decoyPath });
    if (!exists) {
      await invoke("create_decoy_vault", {
        path: decoyPath,
        passphrase,
        cipher: "xchacha20poly1305",
      });
    }
    await invoke("set_duress", { decoyPath, duressPassphrase: passphrase });
    modalDuress.hidden = true;
    modalSettings.hidden = false;
    await refreshSettingsInfo();
    showToast("Mot de passe de contrainte configuré.");
  } catch (e) {
    duressError.hidden = false;
    duressError.textContent = errorMessage(e);
  }
});

// ---------- AtomasDestruct : purge après échecs répétés ----------

const modalAutowipe = el("modal-autowipe");
const autowipeSelect = el("autowipe-select");

el("btn-open-autowipe").addEventListener("click", async () => {
  modalSettings.hidden = true;
  try {
    const info = await invoke("vault_info");
    autowipeSelect.value = String(info.auto_wipe_after ?? 0);
  } catch (e) {
    // ignore, garde la valeur par défaut
  }
  modalAutowipe.hidden = false;
});

el("autowipe-cancel").addEventListener("click", () => {
  modalAutowipe.hidden = true;
  modalSettings.hidden = false;
});

el("autowipe-confirm").addEventListener("click", async () => {
  const value = parseInt(autowipeSelect.value, 10);
  try {
    await invoke("set_auto_wipe", { threshold: value > 0 ? value : null });
    modalAutowipe.hidden = true;
    modalSettings.hidden = false;
    await refreshSettingsInfo();
    showToast(value > 0 ? "Purge automatique activée." : "Purge automatique désactivée.");
  } catch (e) {
    showToast(errorMessage(e), true);
  }
});

// ---------- AtomasDestruct : destruction immédiate ----------

const modalPanic = el("modal-panic");
const panicConfirmInput = el("panic-confirm-input");
const panicConfirmBtn = el("panic-confirm");
const panicError = el("panic-error");

el("btn-open-panic").addEventListener("click", () => {
  modalSettings.hidden = true;
  panicConfirmInput.value = "";
  panicConfirmBtn.disabled = true;
  panicError.hidden = true;
  modalPanic.hidden = false;
});

el("panic-cancel").addEventListener("click", () => {
  modalPanic.hidden = true;
  modalSettings.hidden = false;
});

panicConfirmInput.addEventListener("input", () => {
  panicConfirmBtn.disabled = panicConfirmInput.value !== "DETRUIRE";
});

panicConfirmBtn.addEventListener("click", async () => {
  if (panicConfirmInput.value !== "DETRUIRE") return;
  try {
    await invoke("panic_wipe");
    modalPanic.hidden = true;
    modalSettings.hidden = true;
    await backToLock();
    showToast("Coffre détruit.");
  } catch (e) {
    panicError.hidden = false;
    panicError.textContent = errorMessage(e);
  }
});

init();
