function sendServiceResult(res, result) {
  return res.status(result.status).json(result.body);
}

function createAuthController({ authService }) {
  async function login(req, res) {
    try {
      const result = await authService.login(req.body);
      return sendServiceResult(res, result);
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ result: false, error: err.message });
    }
  }

  async function signup(req, res) {
    try {
      const result = await authService.signup(req.body);
      return sendServiceResult(res, result);
    } catch (err) {
      console.error('Signup error:', err);
      return res.status(500).json({ result: false, error: err.message });
    }
  }

  async function deleteAccount(req, res) {
    try {
      const result = await authService.deleteAccount(req.body);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  async function resetPassword(req, res) {
    try {
      const result = await authService.resetPassword(req.body);
      return sendServiceResult(res, result);
    } catch (e) {
      return res.status(500).json({ result: false, error: e.message });
    }
  }

  return {
    login,
    signup,
    deleteAccount,
    resetPassword,
  };
}

module.exports = createAuthController;
