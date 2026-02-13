# Frontend Integration Guide

Complete guide for integrating the Auth Server with your Angular frontend using **HttpOnly Cookie-based authentication** and **CSRF protection**.

***

## Overview

This Auth Server uses:
- **HttpOnly Cookies**: Tokens stored securely in cookies (immune to XSS)
- **CSRF Protection**: Double-submit cookie pattern with X-CSRF-Token header
- **Automatic Token Refresh**: Seamless UX without interruptions
- **No localStorage**: Tokens never exposed to JavaScript

***

## Prerequisites

- Angular 15+ (uses functional interceptors)
- HttpClient module
- RxJS

***

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Environment Configuration

Create or update `src/environments/environment.ts`:

```typescript
export const environment = {
  production: false,
  authServiceUrl: 'http://localhost:4000'
};
```

***

## Implementation

### 1. App Configuration (app.config.ts)

Configure HttpClient with interceptors and initialize CSRF token on app startup.

```typescript
import { ApplicationConfig, provideAppInitializer } from '@angular/core';
import { provideHttpClient, withInterceptors, withFetch } from '@angular/common/http';
import { inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { Auth } from '@core/services/auth';

export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      withFetch(),
      withInterceptors([
        credentialsInterceptor,  // Send cookies with every request
        csrfInterceptor,          // Add CSRF token header
        authInterceptor,          // Handle 401 and auto-refresh
        errorInterceptor          // Global error handling
      ])
    ),
    // Fetch CSRF token before app starts
    provideAppInitializer(() => {
      const authService = inject(Auth);
      return firstValueFrom(authService.fetchCsrfToken())
        .then(() => console.log('✅ CSRF token initialized'))
        .catch(err => console.error('⚠️ CSRF token fetch failed:', err));
    })
  ]
};
```

***

### 2. Credentials Interceptor

Ensures all HTTP requests include credentials (cookies).

**File:** `src/app/core/interceptors/credentials.interceptor.ts`

```typescript
import { HttpInterceptorFn } from '@angular/common/http';

export const credentialsInterceptor: HttpInterceptorFn = (req, next) => {
  // Always send cookies with requests
  const reqWithCredentials = req.clone({
    withCredentials: true
  });
  return next(reqWithCredentials);
};
```

***

### 3. CSRF Interceptor

Adds X-CSRF-Token header to protected endpoints.

**File:** `src/app/core/interceptors/csrf.interceptor.ts`

```typescript
import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Auth } from '@core/services/auth';

export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(Auth);
  
  // Endpoints that require CSRF protection
  const csrfProtectedEndpoints = [
    '/auth/login',
    '/auth/signup',
    '/auth/change-password',
    '/auth/forgot-password',
    '/auth/reset-password',
    '/auth/revoke-token',
    '/auth/revoke-all-tokens',
    '/auth/profile',
    '/auth/avatar',
    '/admin/users'
  ];
  
  const needsCsrf = csrfProtectedEndpoints.some(endpoint => req.url.includes(endpoint)) 
                    && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method);
  
  if (!needsCsrf) {
    return next(req);
  }
  
  // Add CSRF token to header if available
  const csrfToken = authService.getCsrfToken();
  
  if (csrfToken) {
    const csrfReq = req.clone({
      setHeaders: { 'X-CSRF-Token': csrfToken }
    });
    return next(csrfReq);
  }
  
  // Warning if token is not available (backend will respond with 403)
  console.warn('⚠️ CSRF token not available for protected endpoint:', req.url);
  return next(req);
};
```

***

### 4. Auth Interceptor

Handles 401 errors and automatically refreshes tokens.

**File:** `src/app/core/interceptors/auth.interceptor.ts`

```typescript
import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { catchError, switchMap, throwError } from 'rxjs';
import { Auth } from '@core/services/auth';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const authService = inject(Auth);
  
  // Public endpoints that don't require authentication
  const publicEndpoints = [
    '/auth/login',
    '/auth/signup',
    '/auth/refresh-token',
    '/auth/csrf-token',
    '/auth/forgot-password',
    '/auth/reset-password',
    '/auth/verify-reset-token'
  ];

  const isPublicEndpoint = publicEndpoints.some(endpoint => req.url.includes(endpoint));

  if (isPublicEndpoint) {
    return next(req);
  }

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      // Auto-refresh on 401
      if (error.status === 401 && !req.url.includes('/auth/refresh-token')) {
        return authService.refreshToken().pipe(
          switchMap(() => {
            console.log('✅ [Auth Interceptor] Token refreshed - Retrying original request');
            return next(req);  // Retry original request
          }),
          catchError(refreshError => {
            console.error('❌ [Auth Interceptor] Token refresh failed:', {
              status: refreshError.status,
              error: refreshError.error
            });
            authService.logout().subscribe();
            return throwError(() => refreshError);
          })
        );
      }
      return throwError(() => error);
    })
  );
};
```

***

### 5. Error Interceptor

Global error handler with user-friendly messages.

**File:** `src/app/core/interceptors/error.interceptor.ts`

```typescript
import { inject } from '@angular/core';
import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { catchError, throwError } from 'rxjs';
import { Router } from '@angular/router';
import { Auth } from '@core/services/auth';

export const errorInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const authService = inject(Auth);

  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      let errorMessage = 'An unexpected error occurred';

      if (error.error instanceof ErrorEvent) {
        // Client-side error
        errorMessage = `Error: ${error.error.message}`;
      } else {
        // Server-side error
        errorMessage = error.error?.message || error.message || errorMessage;
        
        // Handle specific HTTP status codes
        switch (error.status) {
          case 0:
            errorMessage = 'Unable to connect to server. Please check your connection.';
            break;
            
          case 401:
            // Skip if auth interceptor is handling the refresh
            if (!req.url.includes('/auth/refresh-token')) {
              return throwError(() => error);  // Let auth interceptor handle it
            }
            errorMessage = 'Session expired. Please login again.';
            authService.logout();
            router.navigate(['/auth/login']);
            break;
            
          case 403:
            errorMessage = 'Access denied. You do not have permission.';
            break;
            
          case 404:
            errorMessage = 'Resource not found.';
            break;
            
          case 422:
            errorMessage = error.error?.message || 'Validation error.';
            break;
            
          case 500:
            errorMessage = 'Server error. Please try again later.';
            break;
            
          case 503:
            errorMessage = 'Service temporarily unavailable.';
            break;
        }
      }

      // Log error for debugging
      console.error('HTTP Error:', {
        status: error.status,
        message: errorMessage,
        url: req.url
      });

      return throwError(() => ({
        status: error.status,
        message: errorMessage,
        error: error.error
      }));
    })
  );
};

```

***

### 6. Auth Service

Core authentication service with reactive state management.

**File:** `src/app/core/services/auth.ts`

```typescript
import { Injectable, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { Observable, tap, catchError, throwError, BehaviorSubject, of, finalize, shareReplay } from 'rxjs';
import { toSignal } from '@angular/core/rxjs-interop';
import { environment } from '@environments/environment';

// Type definitions (add to a separate types file)
export interface User {
  id: string;
  username: string;
  email: string;
  role: 'customer' | 'admin';
  firstName?: string;
  lastName?: string;
  avatar?: string;
}

export interface AuthResponse {
  message: string;
  user: User;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  username: string;
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
}

@Injectable({ providedIn: 'root' })
export class Auth {
  private http = inject(HttpClient);
  private router = inject(Router);
  
  private readonly AUTH_API_URL = environment.authServiceUrl;
  private readonly USER_KEY = 'auth_user';
  
  private csrfToken: string | null = null;
  private refreshInFlight$?: Observable<void>;
  
  // Reactive signals for state management
  private currentUserSubject = new BehaviorSubject<User | null>(this.getUserFromStorage());
  public currentUser$ = this.currentUserSubject.asObservable();
  
  currentUser = toSignal(this.currentUser$, { initialValue: this.getUserFromStorage() });
  isAuthenticated = computed(() => !!this.currentUser());
  isAdmin = computed(() => this.currentUser()?.role === 'admin');
  isLoading = signal(false);
  
  // ==================== PUBLIC METHODS ====================
  
  /**
   * Fetch CSRF token from server
   * Called automatically on app initialization
   */
  fetchCsrfToken(): Observable<{ csrfToken: string }> {
    return this.http.get<{ csrfToken: string }>(
      `${this.AUTH_API_URL}/auth/csrf-token`
    ).pipe(
      tap(res => {
        this.csrfToken = res.csrfToken;
        console.log('✅ CSRF token fetched');
      }),
      catchError(error => {
        console.error('❌ Failed to fetch CSRF token:', error);
        return throwError(() => error);
      })
    );
  }
  
  /**
   * Get current CSRF token
   */
  getCsrfToken(): string | null {
    return this.csrfToken;
  }
  
  /**
   * Register new user
   */
  register(data: RegisterData): Observable<AuthResponse> {
    this.isLoading.set(true);
    
    return this.http.post<AuthResponse>(
      `${this.AUTH_API_URL}/auth/signup`,
      data
    ).pipe(
      tap(response => this.handleAuthSuccess(response)),
      finalize(() => this.isLoading.set(false))
    );
  }
  
  /**
   * Login with credentials
   */
  login(credentials: LoginCredentials): Observable<AuthResponse> {
    this.isLoading.set(true);
    
    return this.http.post<AuthResponse>(
      `${this.AUTH_API_URL}/auth/login`,
      credentials
    ).pipe(
      tap(response => this.handleAuthSuccess(response)),
      finalize(() => this.isLoading.set(false))
    );
  }
  
  /**
   * Refresh access token
   * Prevents multiple simultaneous refresh calls
   */
  refreshToken(): Observable<void> {
    if (this.refreshInFlight$) {
      console.log('🔄 [Auth Service] Refresh already in progress - reusing existing call');
      return this.refreshInFlight$;
    }

    this.refreshInFlight$ = this.http.post<void>(
      `${this.AUTH_API_URL}/auth/refresh-token`,
      {}
    ).pipe(
      tap(() => console.log('✅ [Auth Service] Tokens refreshed successfully')),
      shareReplay(1),
      catchError(error => {
        console.error('❌ [Auth Service] Token refresh failed:', {
          status: error.status,
          message: error.error?.error || error.error?.message || error.message
        });
        return throwError(() => error);
      }),
      finalize(() => {
        console.log('🔓 [Auth Service] Refresh slot released');
        this.refreshInFlight$ = undefined;
      })
    );

    return this.refreshInFlight$;
  }
  
  /**
   * Logout from current device
   * Revokes refresh token on server, then clears local data
   */
  logout(): Observable<void> {
    return this.http.post<void>(
      `${this.AUTH_API_URL}/auth/revoke-token`,
      {}
    ).pipe(
      tap(() => console.log('✅ Token revoked on server')),
      catchError(error => {
        console.error('⚠️ Logout failed, clearing anyway:', error.status);
        return of(void 0);
      }),
      finalize(() => this.clearAuthData())
    );
  }
  
  /**
   * Logout from all devices
   * Revokes all refresh tokens on server, then clears local data
   */
  logoutAllDevices(): Observable<void> {
    return this.http.post<void>(
      `${this.AUTH_API_URL}/auth/revoke-all-tokens`,
      {}
    ).pipe(
      tap(() => console.log('✅ All tokens revoked on server')),
      catchError(error => {
        console.error('⚠️ Revoke all tokens failed, clearing anyway:', error.status);
        return of(void 0);
      }),
      finalize(() => this.clearAuthData())
    );
  }
  
  /**
   * Update current user data
   */
  updateCurrentUser(user: User): void {
    this.currentUserSubject.next(user);
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));
  }
  
  /**
   * Get current user
   */
  getCurrentUser(): User | null {
    return this.currentUserSubject.value;
  }
  
  // ==================== PRIVATE HELPERS ====================
  
  private handleAuthSuccess(response: AuthResponse): void {
    localStorage.setItem(this.USER_KEY, JSON.stringify(response.user));
    this.currentUserSubject.next(response.user);
    
    // NOTE: Add your app-specific post-login logic here
    // Examples:
    // - Sync shopping cart: this.cartService.syncCart(response.user.id)
    // - Load user preferences: this.prefsService.load()
    // - Initialize analytics: this.analytics.identify(response.user)
  }
  
  private clearAuthData(): void {
    localStorage.removeItem(this.USER_KEY);
    this.currentUserSubject.next(null);
    
    // NOTE: Clear app-specific state here
    // Examples:
    // - Clear cart: this.cartService.clearCart()
    // - Reset filters: this.filterService.reset()
    // - Stop timers: this.timerService.stop()
    
    this.router.navigate(['/login']);
  }
  
  private getUserFromStorage(): User | null {
    const userJson = localStorage.getItem(this.USER_KEY);
    return userJson ? JSON.parse(userJson) : null;
  }
}

```

***

## Usage Examples

### Login Component

```typescript
import { Component, inject } from '@angular/core';
import { Auth } from '@core/services/auth';

@Component({
  selector: 'app-login',
  template: `
    <form (ngSubmit)="onSubmit()">
      <input [(ngModel)]="credentials.email" type="email" />
      <input [(ngModel)]="credentials.password" type="password" />
      <button type="submit" [disabled]="authService.isLoading()">
        Login
      </button>
    </form>
  `
})
export class LoginComponent {
  authService = inject(Auth);
  
  credentials = {
    email: '',
    password: ''
  };
  
  onSubmit() {
    this.authService.login(this.credentials).subscribe({
      next: () => console.log('Login successful'),
      error: (err) => console.error('Login failed:', err)
    });
  }
}
```

### Protected Route Guard

```typescript
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { Auth } from '@core/services/auth';

export const authGuard = () => {
  const authService = inject(Auth);
  const router = inject(Router);
  
  if (authService.isAuthenticated()) {
    return true;
  }
  
  router.navigate(['/login']);
  return false;
};
```

### Admin Guard

```typescript
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { Auth } from '@core/services/auth';

export const adminGuard = () => {
  const authService = inject(Auth);
  const router = inject(Router);
  
  if (authService.isAdmin()) {
    return true;
  }
  
  router.navigate(['/']);
  return false;
};
```

***

## Key Features

### ✅ Security
- **HttpOnly Cookies**: Tokens immune to XSS attacks
- **CSRF Protection**: Double-submit cookie pattern
- **Automatic Token Refresh**: Seamless UX
- **No Token Exposure**: Tokens never accessible to JavaScript

### ✅ Developer Experience
- **Reactive State**: Angular signals for reactive UI
- **Type Safety**: Full TypeScript support
- **Error Handling**: Global error interceptor
- **Debugging**: Console logs for troubleshooting

### ✅ Performance
- **Refresh In-Flight Protection**: Prevents duplicate refresh calls
- **ShareReplay**: Efficient observable sharing
- **Automatic Cleanup**: Memory management with finalize

***

## Troubleshooting

### Cookies Not Saved

**Symptoms:**
- 401 errors after login
- Cookies not in DevTools

**Solutions:**
1. Check `ALLOWED_ORIGINS` in backend `.env` includes your frontend URL
2. Leave `COOKIE_DOMAIN` empty for localhost
3. Verify `withCredentials: true` in all requests
4. Clear browser cookies and retry

### CSRF Token Missing

**Symptoms:**
- 403 Forbidden errors
- "CSRF token not available" warnings

**Solutions:**
1. Ensure `provideAppInitializer` is called before routing
2. Check network tab for `/auth/csrf-token` request
3. Verify CSRF interceptor is registered in correct order

### Token Refresh Loop

**Symptoms:**
- Infinite refresh calls
- Console shows multiple refresh attempts

**Solutions:**
1. Check `refreshInFlight$` logic in Auth service
2. Ensure `shareReplay(1)` is present
3. Verify `finalize()` clears the in-flight observable

***

## Production Checklist

Before deploying to production:

- ✅ Update `environment.prod.ts` with production API URL
- ✅ Enable HTTPS (required for secure cookies)
- ✅ Set `COOKIE_SECURE=true` in backend
- ✅ Set `COOKIE_SAMESITE=strict` in backend
- ✅ Configure strict CORS origins
- ✅ Remove console.log statements (or use environment-based logging)
- ✅ Test token refresh flow
- ✅ Test logout from all devices
- ✅ Verify CSRF protection works

***

## Additional Resources

- [Auth Server Documentation](./README.md)
- [Angular HttpClient Guide](https://angular.io/guide/http)
- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

***

**Made by [anp3l](https://github.com/anp3l)**