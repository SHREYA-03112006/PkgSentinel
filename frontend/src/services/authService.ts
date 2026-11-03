import { request } from './apiClient';
import { AuthResponse, LoginPayload, RegisterPayload, UserSummary } from '../types/auth';

const TOKEN_KEY = 'pkgsentinel_auth_token';
const USER_KEY = 'pkgsentinel_user_profile';

export const authStorage = {
  getToken: (): string | null => {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },

  setToken: (token: string): void => {
    try {
      localStorage.setItem(TOKEN_KEY, token);
    } catch {
      // Ignore storage errors in restricted iframe
    }
  },

  getUser: (): UserSummary | null => {
    try {
      const raw = localStorage.getItem(USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  },

  setUser: (user: UserSummary): void => {
    try {
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    } catch {
      // Ignore
    }
  },

  clear: (): void => {
    try {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
    } catch {
      // Ignore
    }
  },
};

/**
 * Register a new user account with Spring Boot backend
 */
export async function registerUser(payload: RegisterPayload): Promise<AuthResponse> {
  const response = await request<AuthResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (response.token && response.user) {
    authStorage.setToken(response.token);
    authStorage.setUser(response.user);
  }

  return response;
}

/**
 * Log in with existing credentials
 */
export async function loginUser(payload: LoginPayload): Promise<AuthResponse> {
  const response = await request<AuthResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  if (response.token && response.user) {
    authStorage.setToken(response.token);
    authStorage.setUser(response.user);
  }

  return response;
}

/**
 * Fetch authenticated profile from backend
 */
export async function fetchCurrentUser(): Promise<UserSummary | null> {
  const token = authStorage.getToken();
  if (!token) return null;

  try {
    const user = await request<UserSummary>('/auth/me');
    authStorage.setUser(user);
    return user;
  } catch (error) {
    // If token expired or invalid, clear cached token
    authStorage.clear();
    return null;
  }
}

/**
 * Log out and clear session both on server and locally
 */
export async function logoutUser(): Promise<void> {
  const token = authStorage.getToken();
  if (token) {
    try {
      await request<void>('/auth/logout', { method: 'POST' });
    } catch {
      // Server-side cleanup best-effort
    }
  }
  authStorage.clear();
}

