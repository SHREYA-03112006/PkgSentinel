import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { UserSummary, LoginPayload, RegisterPayload } from '../types/auth';
import { authStorage, loginUser, registerUser, fetchCurrentUser, logoutUser } from '../services/authService';

interface AuthContextType {
  user: UserSummary | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  authModalOpen: boolean;
  authModalMode: 'signin' | 'signup';
  openAuthModal: (mode?: 'signin' | 'signup') => void;
  closeAuthModal: () => void;
  login: (payload: LoginPayload) => Promise<void>;
  register: (payload: RegisterPayload) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserSummary | null>(() => authStorage.getUser());
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [authModalOpen, setAuthModalOpen] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<'signin' | 'signup'>('signin');

  useEffect(() => {
    let mounted = true;
    const initAuth = async () => {
      const token = authStorage.getToken();
      if (token) {
        try {
          const profile = await fetchCurrentUser();
          if (mounted) {
            setUser(profile);
          }
        } catch {
          if (mounted) {
            setUser(null);
          }
        }
      } else {
        if (mounted) {
          setUser(null);
        }
      }
      if (mounted) {
        setIsLoading(false);
      }
    };

    initAuth();
    return () => {
      mounted = false;
    };
  }, []);

  const openAuthModal = (mode: 'signin' | 'signup' = 'signin') => {
    setAuthModalMode(mode);
    setAuthModalOpen(true);
  };

  const closeAuthModal = () => {
    setAuthModalOpen(false);
  };

  const login = async (payload: LoginPayload) => {
    const response = await loginUser(payload);
    setUser(response.user);
    setAuthModalOpen(false);
  };

  const register = async (payload: RegisterPayload) => {
    const response = await registerUser(payload);
    setUser(response.user);
    setAuthModalOpen(false);
  };

  const logout = async () => {
    await logoutUser();
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        authModalOpen,
        authModalMode,
        openAuthModal,
        closeAuthModal,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
