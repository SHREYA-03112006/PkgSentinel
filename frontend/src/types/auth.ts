export interface UserSummary {
  id: string;
  username: string;
  email: string;
  fullName: string;
  role: string;
}

export interface AuthResponse {
  token: string;
  user: UserSummary;
  message: string;
}

export interface RegisterPayload {
  username: string;
  email: string;
  password: string;
  fullName: string;
}

export interface LoginPayload {
  usernameOrEmail: string;
  password: string;
}
