import {
  createUserWithEmailAndPassword,
  EmailAuthProvider,
  onAuthStateChanged,
  reauthenticateWithCredential,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  signOut,
  updatePassword,
  getAuth
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

import {
  deleteDoc,
  doc,
  getDoc,
  serverTimestamp,
  setDoc,
  updateDoc
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";

import {
  initializeApp,
  getApps,
  deleteApp
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";

import { auth, db, firebaseConfig } from "../firebase-config.js";

/**
 * ============================================================================
 * AUTH SERVICE
 * ============================================================================
 * Compatível com:
 * - login(email, password)
 * - logout()
 * - logoutUser()
 * - changePassword(currentPassword, newPassword)
 * - onUserSession(callback)
 * - getCurrentUserProfile()
 * - createManagedUser(data)
 * - updateManagedUser(uid, data)
 * - setUserActiveStatus(uid, ativo)
 * - softDeleteManagedUser(uid)
 * - sendResetPassword(email)
 * ============================================================================
 */

/* -------------------------------------------------------------------------- */
/* Utils                                                                      */
/* -------------------------------------------------------------------------- */

function isObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function sanitizeString(value) {
  return String(value ?? "").trim();
}

export function normalizeLoginEmail(value) {
  const input = sanitizeString(value).toLowerCase();

  if (!input) return "";
  if (input.includes("@")) return input;

  return `${input}@gestao.local`;
}

function normalizePermissions(permissoes = {}) {
  const base = {
    dashboard: false,
    vendas: false,
    produtos: false,
    relatorios: false,
    tele_entregas: false,
    usuarios: false,
    configuracoes: false,
    estoque: false
  };

  if (!isObject(permissoes)) {
    return base;
  }

  Object.keys(base).forEach((key) => {
    base[key] = permissoes[key] === true;
  });

  return base;
}

function buildUserPayload(data = {}, mode = "create") {
  const now = serverTimestamp();

  const payload = {
    nome: sanitizeString(data.nome),
    usuario: sanitizeString(data.usuario).toLowerCase(),
    email: normalizeLoginEmail(data.email || data.usuario),
    tipo: sanitizeString(data.tipo || "Vendedor"),
    ativo: data.ativo !== false,
    permissoes: normalizePermissions(data.permissoes),
    updatedAt: now
  };

  if (mode === "create") {
    payload.createdAt = now;
    payload.deleted = false;
  }

  return payload;
}

async function getUserDocByUid(uid) {
  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  const ref = doc(db, "users", uid);
  const snap = await getDoc(ref);
  return { ref, snap };
}

function buildFriendlyAuthError(error) {
  const code = error?.code || "";

  switch (code) {
    case "auth/invalid-credential":
    case "auth/wrong-password":
    case "auth/user-not-found":
    case "auth/invalid-login-credentials":
      return new Error("Usuário ou senha inválidos.");

    case "auth/invalid-email":
      return new Error("E-mail inválido.");

    case "auth/email-already-in-use":
      return new Error("Este e-mail já está em uso.");

    case "auth/weak-password":
      return new Error("A senha precisa ter pelo menos 6 caracteres.");

    case "auth/too-many-requests":
      return new Error("Muitas tentativas. Tente novamente em instantes.");

    case "auth/requires-recent-login":
      return new Error("Por segurança, faça login novamente antes de alterar a senha.");

    case "permission-denied":
      return new Error("Sem permissão para acessar os dados no Firestore.");

    default:
      return error instanceof Error
        ? error
        : new Error("Ocorreu um erro inesperado na autenticação.");
  }
}

/* -------------------------------------------------------------------------- */
/* Login / Sessão                                                             */
/* -------------------------------------------------------------------------- */

export async function login(email, password) {
  try {
    const loginEmail = normalizeLoginEmail(email);

    if (!loginEmail) {
      throw new Error("Informe o usuário ou e-mail.");
    }

    if (!password) {
      throw new Error("Informe a senha.");
    }

    const cred = await signInWithEmailAndPassword(auth, loginEmail, password);
    const authUser = cred.user;

    const { snap } = await getUserDocByUid(authUser.uid);

    if (!snap.exists()) {
      await signOut(auth);
      throw new Error(
        "Perfil do usuário não encontrado no Firestore. Crie o documento na coleção users usando o UID do Authentication."
      );
    }

    const profile = snap.data();

    if (profile.deleted === true) {
      await signOut(auth);
      throw new Error("Usuário excluído logicamente. Acesso bloqueado.");
    }

    if (profile.ativo !== true) {
      await signOut(auth);
      throw new Error("Usuário inativo. Acesso bloqueado.");
    }

    return {
      uid: authUser.uid,
      auth: authUser,
      profile
    };
  } catch (error) {
    console.error("Erro no login:", error);
    throw buildFriendlyAuthError(error);
  }
}

export async function logoutUser() {
  await signOut(auth);
}

export const logout = logoutUser;

export function getCurrentAuthUser() {
  return auth.currentUser || null;
}

export async function getCurrentUserProfile() {
  const currentUser = auth.currentUser;

  if (!currentUser) {
    return null;
  }

  const { snap } = await getUserDocByUid(currentUser.uid);

  if (!snap.exists()) {
    return null;
  }

  return {
    uid: currentUser.uid,
    ...snap.data()
  };
}

export function onUserSession(callback) {
  return onAuthStateChanged(auth, async (user) => {
    try {
      if (!user) {
        callback(null);
        return;
      }

      const { snap } = await getUserDocByUid(user.uid);

      if (!snap.exists()) {
        callback({
          uid: user.uid,
          auth: user,
          profile: null,
          status: "missing-profile"
        });
        return;
      }

      const profile = snap.data();

      callback({
        uid: user.uid,
        auth: user,
        profile,
        status: profile.ativo === true ? "active" : "inactive"
      });
    } catch (error) {
      console.error("Erro ao carregar sessão:", error);
      callback({
        uid: user?.uid || null,
        auth: user || null,
        profile: null,
        status: "error",
        error
      });
    }
  });
}

export function waitForAuthReady() {
  return new Promise((resolve) => {
    const unsub = onAuthStateChanged(auth, (user) => {
      unsub();
      resolve(user || null);
    });
  });
}

/* -------------------------------------------------------------------------- */
/* Senha                                                                      */
/* -------------------------------------------------------------------------- */

export async function changePassword(currentPassword, newPassword) {
  const user = auth.currentUser;

  if (!user) {
    throw new Error("Nenhum usuário autenticado.");
  }

  if (!currentPassword) {
    throw new Error("Informe a senha atual.");
  }

  if (!newPassword || String(newPassword).length < 6) {
    throw new Error("A nova senha precisa ter pelo menos 6 caracteres.");
  }

  try {
    const credential = EmailAuthProvider.credential(user.email, currentPassword);
    await reauthenticateWithCredential(user, credential);
    await updatePassword(user, newPassword);
    return true;
  } catch (error) {
    console.error("Erro ao trocar senha:", error);
    throw buildFriendlyAuthError(error);
  }
}

export async function sendResetPassword(email) {
  const normalizedEmail = normalizeLoginEmail(email);

  if (!normalizedEmail) {
    throw new Error("Informe um e-mail válido.");
  }

  try {
    await sendPasswordResetEmail(auth, normalizedEmail);
    return true;
  } catch (error) {
    console.error("Erro ao enviar redefinição de senha:", error);
    throw buildFriendlyAuthError(error);
  }
}

/* -------------------------------------------------------------------------- */
/* Gestão de Usuários                                                         */
/* -------------------------------------------------------------------------- */

async function createSecondaryAppAndAuth() {
  const appName = `user-creator-${Date.now()}`;

  const secondaryApp = initializeApp(firebaseConfig, appName);
  const secondaryAuth = getAuth(secondaryApp);

  return { secondaryApp, secondaryAuth };
}

async function destroySecondaryApp(appInstance) {
  if (!appInstance) return;

  try {
    await deleteApp(appInstance);
  } catch (error) {
    console.warn("Não foi possível destruir app secundário:", error);
  }
}

export async function createManagedUser(data = {}) {
  const currentUser = auth.currentUser;

  if (!currentUser) {
    throw new Error("Você precisa estar autenticado para cadastrar usuários.");
  }

  const nome = sanitizeString(data.nome);
  const usuario = sanitizeString(data.usuario).toLowerCase();
  const senha = sanitizeString(data.senha);
  const email = normalizeLoginEmail(data.email || usuario);

  if (!nome) throw new Error("Informe o nome completo.");
  if (!usuario) throw new Error("Informe o usuário.");
  if (!senha || senha.length < 6) {
    throw new Error("A senha precisa ter pelo menos 6 caracteres.");
  }
  if (!email) throw new Error("Informe um e-mail válido.");

  let secondaryApp = null;
  let secondaryAuth = null;

  try {
    ({ secondaryApp, secondaryAuth } = await createSecondaryAppAndAuth());

    const credential = await createUserWithEmailAndPassword(secondaryAuth, email, senha);
    const createdUser = credential.user;

    const payload = buildUserPayload(
      {
        ...data,
        email,
        usuario,
        nome
      },
      "create"
    );

    payload.uid = createdUser.uid;

    await setDoc(doc(db, "users", createdUser.uid), payload);

    await signOut(secondaryAuth);

    return {
      uid: createdUser.uid,
      ...payload
    };
  } catch (error) {
    console.error("Erro ao criar usuário:", error);
    throw buildFriendlyAuthError(error);
  } finally {
    await destroySecondaryApp(secondaryApp);
  }
}

export async function updateManagedUser(uid, data = {}) {
  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  const updates = buildUserPayload(data, "update");

  if (!updates.nome) delete updates.nome;
  if (!updates.usuario) delete updates.usuario;
  if (!updates.email) delete updates.email;
  if (!updates.tipo) delete updates.tipo;

  if (!isObject(data.permissoes)) {
    delete updates.permissoes;
  }

  if (typeof data.ativo !== "boolean") {
    delete updates.ativo;
  }

  await updateDoc(doc(db, "users", uid), updates);
  return true;
}

export async function setUserActiveStatus(uid, ativo) {
  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  await updateDoc(doc(db, "users", uid), {
    ativo: ativo === true,
    updatedAt: serverTimestamp()
  });

  return true;
}

export async function softDeleteManagedUser(uid) {
  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  await updateDoc(doc(db, "users", uid), {
    ativo: false,
    deleted: true,
    updatedAt: serverTimestamp()
  });

  return true;
}

export async function hardDeleteUserDoc(uid) {
  if (!uid) {
    throw new Error("UID do usuário não informado.");
  }

  await deleteDoc(doc(db, "users", uid));
  return true;
}

/* -------------------------------------------------------------------------- */
/* Helpers de permissão                                                       */
/* -------------------------------------------------------------------------- */

export function hasPermission(profile, area) {
  if (!profile || !area) return false;

  if (profile.tipo === "Gerente") return true;

  return profile?.permissoes?.[area] === true;
}

export function isUserActive(profile) {
  return profile?.ativo === true && profile?.deleted !== true;
}

export function isAdmin(profile) {
  return profile?.tipo === "Gerente" && isUserActive(profile);
}

/* -------------------------------------------------------------------------- */
/* Aliases de compatibilidade                                                 */
/* -------------------------------------------------------------------------- */

export const createUser = createManagedUser;
export const updateUser = updateManagedUser;
export const toggleUserStatus = setUserActiveStatus;
export const deleteUserSoft = softDeleteManagedUser;
export const forgotPassword = sendResetPassword;
