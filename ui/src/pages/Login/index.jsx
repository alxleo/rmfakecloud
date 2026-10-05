import React, { useEffect, useState } from "react";
import { useHistory } from "react-router-dom";
import { Button, Form } from "react-bootstrap";

import { useAuthState } from "../../common/useAuthContext";
import { loginUser } from "../../common/actions";
import apiService from "../../services/api.service";

import styles from "./Login.module.scss";

const Login = () => {
  let history = useHistory();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authConfig, setAuthConfig] = useState(null);
  const [authConfigStatus, setAuthConfigStatus] = useState("loading");

  const { state, dispatch } = useAuthState(); //read the values of loading and errorMessage from context
  const { errorMessage, loading } = state;

  useEffect(() => {
    let active = true;
    apiService.authConfig()
      .then((config) => {
        if (!active) return;
        setAuthConfig(config);
        setAuthConfigStatus("ready");
      })
      .catch(() => {
        if (active) setAuthConfigStatus("error");
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (
      authConfigStatus === "ready" &&
      authConfig?.local_login_enabled !== true &&
      authConfig?.oidc_login_url
    ) {
      window.location.assign(authConfig.oidc_login_url);
    }
  }, [authConfig, authConfigStatus]);

  const handleLogin = async (e) => {
    e.preventDefault();

    let payload = { email: username, password };
    try {
      await loginUser(dispatch, payload);
      history.push("/documents"); //TODO: usenavigate or return redirect
    } catch (error) {
      console.log(error);
    }
  };

  if (authConfigStatus !== "ready" || authConfig?.local_login_enabled !== true) {
    let message = "Loading login options…";
    if (authConfigStatus === "error") {
      message = "Unable to load login options.";
    } else if (authConfigStatus === "ready") {
      message = authConfig?.oidc_login_url
        ? "Redirecting to single sign-on…"
        : "Single sign-on is not configured.";
    }

    return (
      <div className={styles.container}>
        <div className={styles.formContainer}>
          <p>{message}</p>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.formContainer}>
        {errorMessage ? <p className={styles.error}>{errorMessage}</p> : null}

        <Form>
          <Form.Group className="mb-3">
            <Form.Label htmlFor="username">Username</Form.Label>
            <Form.Control
              id="username"
              value={username}
              autoFocus
              onChange={(e) => setUsername(e.target.value)}
              disabled={loading}
              placeholder="Username" 
              autoComplete="username"
              />
          </Form.Group>

          <Form.Group className="mb-3">
            <Form.Label htmlFor="password">Password</Form.Label>
            <Form.Control
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
              placeholder="Password" 
              autoComplete="current-password"
              />
          </Form.Group>

          <Button type="submit" onClick={handleLogin} disabled={loading}>
            Login
          </Button>

          {authConfig?.oidc_enabled ? (
            <Button
              variant="outline-primary"
              type="button"
              onClick={() => window.location.assign(authConfig.oidc_login_url)}
              disabled={loading}
            >
              {authConfig.oidc_display_name || "Login with OIDC"}
            </Button>
          ) : null}
        </Form>

      </div>
    </div>
  );
};

export default Login;
