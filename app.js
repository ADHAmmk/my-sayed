"use strict";

const STORAGE_KEY = "personal-records.v1";
const ITERATIONS = 310000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const categories = [
  {
    id: "clinics",
    name: "عيادات جامعة المنصورة",
    icon: "✚",
    description: "بيانات المرضى ومواعيد العيادات",
    fields: [
      { key: "patient", label: "اسم المريض", required: true },
      { key: "nationalId", label: "الرقم القومي", inputMode: "numeric" },
      { key: "mobile", label: "المحمول", inputMode: "tel" },
      { key: "hospital", label: "المستشفى" },
      { key: "clinic", label: "العيادة" },
      { key: "condition", label: "مرض المصاب به" },
      { key: "password", label: "كلمة السر", kind: "password" },
      { key: "notes", label: "ملاحظات", kind: "textarea", wide: true }
    ]
  },
  {
    id: "sites",
    name: "مواقع هامة",
    icon: "◎",
    description: "روابط ومعلومات المواقع المهمة",
    fields: [
      { key: "name", label: "اسم الموقع", required: true },
      { key: "url", label: "رابط الموقع", inputMode: "url", placeholder: "https://example.com" },
      { key: "description", label: "الوصف", kind: "textarea", wide: true }
    ]
  },
  {
    id: "publicSecurity",
    name: "الأمن العام",
    icon: "▣",
    description: "البيانات الشخصية والمستندات",
    fields: [
      { key: "name", label: "الاسم", required: true },
      { key: "nationalId", label: "الرقم القومي", inputMode: "numeric" },
      { key: "residenceNumber", label: "رقم الإقامة", sensitive: true },
      { key: "passportNumber", label: "رقم الجواز", sensitive: true },
      { key: "mobile", label: "المحمول", inputMode: "tel" },
      { key: "lastTravel", label: "تاريخ آخر سفر", kind: "date" },
      { key: "returnDate", label: "تاريخ العودة", kind: "date" },
      { key: "profession", label: "المهنة" },
      { key: "organization", label: "الشركة أو المؤسسة" },
      { key: "qualification", label: "المؤهل" },
      { key: "qualificationYear", label: "سنة المؤهل", inputMode: "numeric" },
      { key: "motherName", label: "اسم الأم" },
      { key: "passportIssueDate", label: "تاريخ إصدار الجواز", kind: "date" },
      { key: "email", label: "الإيميل", kind: "email", sensitive: true },
      { key: "factoryNumber", label: "رقم المصنع", sensitive: true },
      { key: "pin", label: "PIN", sensitive: true, kind: "password" },
      { key: "password", label: "كلمة السر", kind: "password" },
      { key: "notes", label: "ملاحظات", kind: "textarea", wide: true }
    ]
  },
  {
    id: "passwords",
    name: "كلمات مرور هامة",
    icon: "⌑",
    description: "حسابات الدخول وكلمات المرور",
    fields: [
      { key: "site", label: "اسم الموقع", required: true },
      { key: "password", label: "كلمة السر", kind: "password" },
      { key: "notes", label: "ملاحظات", kind: "textarea", wide: true },
      { key: "comments", label: "تعليقات", kind: "textarea", wide: true }
    ]
  }
];

const authScreen = document.querySelector("#authScreen");
const appScreen = document.querySelector("#appScreen");
const setupForm = document.querySelector("#setupForm");
const unlockForm = document.querySelector("#unlockForm");
const authMessage = document.querySelector("#authMessage");
const appMessage = document.querySelector("#appMessage");
const categoryNav = document.querySelector("#categoryNav");
const sectionTitle = document.querySelector("#sectionTitle");
const tableHead = document.querySelector("#tableHead");
const tableBody = document.querySelector("#tableBody");
const emptyState = document.querySelector("#emptyState");
const searchInput = document.querySelector("#searchInput");
const recordCount = document.querySelector("#recordCount");
const recordDialog = document.querySelector("#recordDialog");
const recordForm = document.querySelector("#recordForm");
const recordFields = document.querySelector("#recordFields");
const passwordDialog = document.querySelector("#passwordDialog");
const passwordForm = document.querySelector("#passwordForm");

let activeCategoryId = categories[0].id;
let records = emptyRecords();
let activeKey = null;
let activeSalt = null;
let editingRecordId = null;
let saveQueue = Promise.resolve();

function emptyRecords() {
  return Object.fromEntries(categories.map((category) => [category.id, []]));
}

function currentCategory() {
  return categories.find((category) => category.id === activeCategoryId);
}

function normalizeWebsiteUrl(value) {
  if (!value) return "";
  const candidate = /^[a-z][a-z\d+.-]*:/i.test(value) ? value : `https://${value}`;
  try {
    const url = new URL(candidate);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}

function setMessage(element, text, isSuccess) {
  element.textContent = text;
  element.classList.toggle("success", Boolean(isSuccess));
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function createEnvelope(value, key, salt) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(value))
  );
  return JSON.stringify({
    version: 1,
    iterations: ITERATIONS,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted))
  });
}

function readEnvelope() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) throw new Error("لا توجد بيانات مشفّرة.");
  const envelope = JSON.parse(raw);
  if (
    envelope.version !== 1 ||
    envelope.iterations !== ITERATIONS ||
    typeof envelope.salt !== "string" ||
    typeof envelope.iv !== "string" ||
    typeof envelope.data !== "string"
  ) {
    throw new Error("تنسيق البيانات المشفّرة غير صالح.");
  }
  return envelope;
}

async function decryptEnvelope(envelope, key) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(envelope.iv) },
    key,
    base64ToBytes(envelope.data)
  );
  return JSON.parse(decoder.decode(plaintext));
}

function validateRecords(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return categories.every((category) =>
    Array.isArray(value[category.id]) &&
    value[category.id].every((item) =>
      item && typeof item === "object" && typeof item.id === "string" && !Array.isArray(item)
    )
  );
}

function showAuth() {
  authScreen.hidden = false;
  appScreen.hidden = true;
  let hasData = false;
  let storageAvailable = true;
  try {
    hasData = Boolean(localStorage.getItem(STORAGE_KEY));
  } catch {
    storageAvailable = false;
  }
  setupForm.hidden = hasData;
  unlockForm.hidden = !hasData;
  const secureOrigin = location.protocol === "https:" || location.hostname === "localhost" || location.hostname === "127.0.0.1";
  const authNotice = !storageAvailable
    ? "تعذر الوصول إلى تخزين المتصفح. فعّل التخزين المحلي لهذا الموقع ثم أعد تحميله."
    : !secureOrigin
      ? "لأمان التشفير، افتح الموقع عبر HTTPS أو localhost."
      : "";
  setMessage(authMessage, authNotice, false);
  if (hasData) document.querySelector("#unlockPassword").focus();
  else document.querySelector("#setupPassword").focus();
}

function showApp() {
  authScreen.hidden = true;
  appScreen.hidden = false;
  searchInput.value = "";
  renderApp();
}

async function persist() {
  const snapshot = structuredClone(records);
  const save = saveQueue.catch(() => {}).then(async () => {
    const encrypted = await createEnvelope(snapshot, activeKey, activeSalt);
    localStorage.setItem(STORAGE_KEY, encrypted);
  });
  saveQueue = save;
  await save;
}

function renderNavigation() {
  categoryNav.replaceChildren();
  for (const category of categories) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "category-card";
    button.setAttribute("aria-pressed", String(category.id === activeCategoryId));
    button.setAttribute("aria-label", `${category.name}، ${records[category.id].length} سجل`);

    const icon = document.createElement("span");
    icon.className = "category-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = category.icon;
    const name = document.createElement("span");
    name.className = "category-name";
    name.textContent = category.name;
    const count = document.createElement("span");
    count.className = "category-count";
    count.textContent = `${records[category.id].length} سجل`;
    button.append(icon, name, count);
    button.addEventListener("click", () => {
      activeCategoryId = category.id;
      searchInput.value = "";
      renderApp();
    });
    categoryNav.append(button);
  }
}

function makeCell(value) {
  const cell = document.createElement("td");
  cell.textContent = value || "—";
  cell.title = value || "";
  return cell;
}

function matchesSearch(record, category, query) {
  if (!query) return true;
  return category.fields.some((field) => String(record[field.key] || "").toLocaleLowerCase("ar").includes(query));
}

function renderTable() {
  const category = currentCategory();
  sectionTitle.textContent = category.name;
  tableHead.replaceChildren();
  tableBody.replaceChildren();

  const headerRow = document.createElement("tr");
  const numberHeader = document.createElement("th");
  numberHeader.scope = "col";
  numberHeader.textContent = "م";
  headerRow.append(numberHeader);
  for (const field of category.fields) {
    const header = document.createElement("th");
    header.scope = "col";
    header.textContent = field.label;
    headerRow.append(header);
  }
  const actionsHeader = document.createElement("th");
  actionsHeader.scope = "col";
  actionsHeader.textContent = "إجراءات";
  headerRow.append(actionsHeader);
  tableHead.append(headerRow);

  const query = searchInput.value.trim().toLocaleLowerCase("ar");
  const visibleRecords = records[category.id].filter((record) => matchesSearch(record, category, query));
  recordCount.textContent = `${visibleRecords.length} من ${records[category.id].length} سجل`;
  emptyState.hidden = visibleRecords.length > 0;

  visibleRecords.forEach((record, index) => {
    const row = document.createElement("tr");
    const numberCell = makeCell(String(index + 1));
    numberCell.className = "row-number";
    row.append(numberCell);

    for (const field of category.fields) {
      const cell = document.createElement("td");
      const value = String(record[field.key] || "");
      if (category.id === "sites" && field.key === "url" && value) {
        const href = normalizeWebsiteUrl(value);
        if (href) {
          const link = document.createElement("a");
          link.className = "record-link";
          link.href = href;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          link.textContent = value;
          cell.append(link);
        } else {
          cell.textContent = value;
        }
      } else if (field.sensitive && value) {
        const content = document.createElement("span");
        content.className = "cell-sensitive";
        const text = document.createElement("span");
        text.textContent = "••••••";
        text.dataset.value = value;
        const reveal = document.createElement("button");
        reveal.type = "button";
        reveal.className = "reveal-button";
        reveal.textContent = "إظهار";
        reveal.setAttribute("aria-label", `إظهار ${field.label}`);
        reveal.addEventListener("click", () => {
          const isHidden = text.textContent === "••••••";
          text.textContent = isHidden ? text.dataset.value : "••••••";
          reveal.textContent = isHidden ? "إخفاء" : "إظهار";
          reveal.setAttribute("aria-label", `${isHidden ? "إخفاء" : "إظهار"} ${field.label}`);
        });
        content.append(text, reveal);
        cell.append(content);
      } else {
        cell.textContent = value || "—";
      }
      row.append(cell);
    }

    const actionsCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const editButton = document.createElement("button");
    editButton.type = "button";
    editButton.className = "row-action";
    editButton.textContent = "تعديل";
    editButton.addEventListener("click", () => openRecordDialog(record));
    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "row-action delete";
    deleteButton.textContent = "حذف";
    deleteButton.addEventListener("click", () => deleteRecord(record.id));
    actions.append(editButton, deleteButton);
    actionsCell.append(actions);
    row.append(actionsCell);
    tableBody.append(row);
  });
}

function renderApp() {
  renderNavigation();
  renderTable();
}

function openRecordDialog(record) {
  const category = currentCategory();
  editingRecordId = record ? record.id : null;
  document.querySelector("#recordDialogTitle").textContent = record ? "تعديل سجل" : "إضافة سجل";
  recordForm.reset();
  recordFields.replaceChildren();

  for (const field of category.fields) {
    const wrapper = document.createElement("div");
    wrapper.className = `form-field${field.wide ? " full-width" : ""}`;
    const label = document.createElement("label");
    const input = document.createElement(field.kind === "textarea" ? "textarea" : "input");
    const inputId = `record-${field.key}`;
    label.htmlFor = inputId;
    label.textContent = field.label;
    input.id = inputId;
    input.name = field.key;
    if (field.kind !== "textarea") input.type = field.kind || "text";
    if (field.inputMode) input.inputMode = field.inputMode;
    if (field.placeholder) input.placeholder = field.placeholder;
    if (field.required) input.required = true;
    if (record && record[field.key]) input.value = record[field.key];
    wrapper.append(label, input);
    recordFields.append(wrapper);
  }
  recordDialog.showModal();
  recordFields.querySelector("input, textarea")?.focus();
}

async function deleteRecord(id) {
  if (!window.confirm("هل تريد حذف هذا السجل نهائيًا؟")) return;
  const category = currentCategory();
  const previous = records[category.id];
  records[category.id] = previous.filter((record) => record.id !== id);
  try {
    await persist();
    setMessage(appMessage, "", true);
    renderApp();
  } catch {
    records[category.id] = previous;
    setMessage(appMessage, "تعذر حفظ التغيير. تحقق من مساحة التخزين ثم أعد المحاولة.", false);
  }
}

setupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = document.querySelector("#setupPassword").value;
  const confirmation = document.querySelector("#setupPasswordConfirm").value;
  if (password.length < 12) {
    setMessage(authMessage, "يجب أن تتكون كلمة المرور من 12 حرفًا على الأقل.", false);
    return;
  }
  if (password !== confirmation) {
    setMessage(authMessage, "كلمتا المرور غير متطابقتين.", false);
    return;
  }
  if (!crypto.subtle) {
    setMessage(authMessage, "التشفير غير متاح. افتح الموقع عبر HTTPS أو localhost في متصفح حديث.", false);
    return;
  }
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);
    records = emptyRecords();
    activeKey = key;
    activeSalt = salt;
    localStorage.setItem(STORAGE_KEY, await createEnvelope(records, activeKey, activeSalt));
    setupForm.reset();
    showApp();
  } catch {
    activeKey = null;
    activeSalt = null;
    setMessage(authMessage, "تعذر إنشاء الدفتر أو حفظه في هذا المتصفح.", false);
  }
});

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!crypto.subtle) {
    setMessage(authMessage, "التشفير غير متاح. افتح الموقع عبر HTTPS أو localhost في متصفح حديث.", false);
    return;
  }
  const password = document.querySelector("#unlockPassword").value;
  try {
    const envelope = readEnvelope();
    const salt = base64ToBytes(envelope.salt);
    const key = await deriveKey(password, salt);
    const decrypted = await decryptEnvelope(envelope, key);
    if (!validateRecords(decrypted)) throw new Error("البيانات غير صالحة.");
    records = decrypted;
    activeKey = key;
    activeSalt = salt;
    unlockForm.reset();
    showApp();
  } catch {
    setMessage(authMessage, "تعذر فتح الدفتر. تحقق من كلمة المرور أو من سلامة البيانات المحفوظة.", false);
  }
});

recordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const category = currentCategory();
  const formData = new FormData(recordForm);
  const record = Object.fromEntries(category.fields.map((field) => [field.key, String(formData.get(field.key) || "").trim()]));
  if (category.id === "sites" && record.url) {
    const url = normalizeWebsiteUrl(record.url);
    if (!url) {
      setMessage(appMessage, "أدخل رابطًا صحيحًا يبدأ بـ http:// أو https://.", false);
      recordForm.elements.namedItem("url").focus();
      return;
    }
    record.url = url;
  }
  record.id = editingRecordId || crypto.randomUUID();
  const collection = records[category.id];
  const previous = collection.slice();
  if (editingRecordId) {
    records[category.id] = collection.map((item) => item.id === editingRecordId ? record : item);
  } else {
    records[category.id] = [...collection, record];
  }
  const submitButton = recordForm.querySelector('button[type="submit"]');
  submitButton.disabled = true;
  try {
    await persist();
    setMessage(appMessage, "", true);
    recordDialog.close();
    renderApp();
  } catch {
    records[category.id] = previous;
    setMessage(appMessage, "تعذر حفظ السجل. تحقق من مساحة التخزين ثم أعد المحاولة.", false);
  } finally {
    submitButton.disabled = false;
  }
});

searchInput.addEventListener("input", renderTable);
document.querySelector("#addRecordButton").addEventListener("click", () => openRecordDialog(null));
document.querySelector("#lockButton").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  await saveQueue.catch(() => {});
  records = emptyRecords();
  activeKey = null;
  activeSalt = null;
  saveQueue = Promise.resolve();
  tableBody.replaceChildren();
  tableHead.replaceChildren();
  categoryNav.replaceChildren();
  searchInput.value = "";
  recordForm.reset();
  passwordForm.reset();
  recordDialog.close();
  passwordDialog.close();
  showAuth();
  button.disabled = false;
});
document.querySelector("#changePasswordButton").addEventListener("click", () => {
  passwordForm.reset();
  setMessage(document.querySelector("#passwordMessage"), "", false);
  passwordDialog.showModal();
  document.querySelector("#currentPassword").focus();
});

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const currentPassword = document.querySelector("#currentPassword").value;
  const newPassword = document.querySelector("#newPassword").value;
  const confirmation = document.querySelector("#newPasswordConfirm").value;
  const message = document.querySelector("#passwordMessage");
  if (newPassword.length < 12) {
    setMessage(message, "يجب أن تتكون كلمة المرور الجديدة من 12 حرفًا على الأقل.", false);
    return;
  }
  if (newPassword !== confirmation) {
    setMessage(message, "كلمتا المرور الجديدتان غير متطابقتين.", false);
    return;
  }
  try {
    await saveQueue;
    const oldEnvelope = readEnvelope();
    const oldKey = await deriveKey(currentPassword, base64ToBytes(oldEnvelope.salt));
    await decryptEnvelope(oldEnvelope, oldKey);
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    const newKey = await deriveKey(newPassword, newSalt);
    const newEnvelope = await createEnvelope(records, newKey, newSalt);
    localStorage.setItem(STORAGE_KEY, newEnvelope);
    activeKey = newKey;
    activeSalt = newSalt;
    passwordForm.reset();
    passwordDialog.close();
  } catch {
    setMessage(message, "تعذر تغيير كلمة المرور. تحقق من كلمة المرور الحالية أو من مساحة التخزين.", false);
  }
});

document.querySelectorAll("[data-close]").forEach((button) => {
  button.addEventListener("click", () => document.getElementById(button.dataset.close).close());
});

showAuth();
