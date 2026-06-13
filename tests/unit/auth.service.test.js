const jwt = require('jsonwebtoken');

const createAuthService = require('../../server/modules/auth/auth.service');
const { hashPassword } = require('../../functions/hash.cjs');

const JWT_SECRET = 'test-secret';

function createAuthRepository(overrides = {}) {
  return {
    findUserByUsername: vi.fn().mockResolvedValue(null),
    updateLastLogin: vi.fn().mockResolvedValue({}),
    insertUser: vi.fn().mockResolvedValue({ insertedId: 'inserted-user-id' }),
    deleteUser: vi.fn().mockResolvedValue({ deletedCount: 1 }),
    updatePassword: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
    ...overrides,
  };
}

function createService(authRepository) {
  return createAuthService({ authRepository, JWT_SECRET });
}

describe('auth.service', () => {
  describe('login', () => {
    it('returns 400 when email or password is missing', async () => {
      const authRepository = createAuthRepository();
      const service = createService(authRepository);

      await expect(service.login({ email: '', password: 'secret' })).resolves.toEqual({
        status: 400,
        body: { result: false, error: 'Email and password are required.' },
      });

      expect(authRepository.findUserByUsername).not.toHaveBeenCalled();
    });

    it('returns 401 when the user does not exist', async () => {
      const authRepository = createAuthRepository();
      const service = createService(authRepository);

      await expect(
        service.login({ email: 'missing@example.com', password: 'secret' })
      ).resolves.toEqual({
        status: 401,
        body: { result: false, error: 'Invalid email or password.' },
      });

      expect(authRepository.findUserByUsername).toHaveBeenCalledWith('missing@example.com');
      expect(authRepository.updateLastLogin).not.toHaveBeenCalled();
    });

    it('returns 401 when a normal user password does not match the stored hash', async () => {
      const authRepository = createAuthRepository({
        findUserByUsername: vi.fn().mockResolvedValue({
          _id: 'user-1',
          username: 'user@example.com',
          email: 'user@example.com',
          password: 'wrong-hash',
          is_admin: false,
        }),
      });
      const service = createService(authRepository);

      await expect(
        service.login({ email: 'user@example.com', password: 'secret' })
      ).resolves.toEqual({
        status: 401,
        body: { result: false, error: 'Invalid email or password.' },
      });

      expect(authRepository.updateLastLogin).not.toHaveBeenCalled();
    });

    it('returns a signed token when a normal user password matches the stored hash', async () => {
      const password = 'secret';
      const user = {
        _id: 'user-1',
        username: 'user@example.com',
        email: 'user@example.com',
        password: await hashPassword(password),
        is_admin: false,
      };
      const authRepository = createAuthRepository({
        findUserByUsername: vi.fn().mockResolvedValue(user),
      });
      const service = createService(authRepository);

      const result = await service.login({ email: user.email, password });

      expect(result.status).toBe(200);
      expect(result.body).toMatchObject({
        result: true,
        message: 'Login successful.',
        user,
      });
      expect(jwt.verify(result.body.token, JWT_SECRET)).toMatchObject({
        userId: user._id,
        username: user.username,
        email: user.email,
        is_admin: user.is_admin,
      });
      expect(authRepository.updateLastLogin).toHaveBeenCalledWith(user.email);
    });

    it('checks admin login against the plain stored password', async () => {
      const user = {
        _id: 'admin-1',
        username: 'admin@example.com',
        email: 'admin@example.com',
        password: 'admin-secret',
        is_admin: true,
      };
      const authRepository = createAuthRepository({
        findUserByUsername: vi.fn().mockResolvedValue(user),
      });
      const service = createService(authRepository);

      const result = await service.login({
        email: user.email,
        password: 'admin-secret',
        type: 'Admin',
      });

      expect(result.status).toBe(200);
      expect(authRepository.updateLastLogin).toHaveBeenCalledWith(user.email);
    });
  });

  describe('signup', () => {
    it('returns 400 when email or password is missing', async () => {
      const authRepository = createAuthRepository();
      const service = createService(authRepository);

      await expect(service.signup({ email: 'new@example.com', password: '' })).resolves.toEqual({
        status: 400,
        body: { result: false, error: 'Email and password are required.' },
      });

      expect(authRepository.insertUser).not.toHaveBeenCalled();
    });

    it('returns a duplicate email response when the email already exists', async () => {
      const authRepository = createAuthRepository({
        findUserByUsername: vi.fn().mockResolvedValue({ email: 'taken@example.com' }),
      });
      const service = createService(authRepository);

      await expect(
        service.signup({ email: 'taken@example.com', password: 'secret' })
      ).resolves.toEqual({
        status: 200,
        body: { result: false, error: 'Email already taken' },
      });

      expect(authRepository.insertUser).not.toHaveBeenCalled();
    });

    it('hashes the password and inserts a new non-admin user', async () => {
      const authRepository = createAuthRepository();
      const service = createService(authRepository);

      await expect(
        service.signup({ email: 'new@example.com', password: 'secret' })
      ).resolves.toEqual({
        status: 200,
        body: { result: true, message: 'Account registered successfully.' },
      });

      expect(authRepository.insertUser).toHaveBeenCalledWith(
        expect.objectContaining({
          username: 'new@example.com',
          email: 'new@example.com',
          password: await hashPassword('secret'),
          is_admin: false,
          last_login: expect.any(Date),
        })
      );
    });
  });

  describe('deleteAccount', () => {
    it('returns 400 when username is missing', async () => {
      const authRepository = createAuthRepository();
      const service = createService(authRepository);

      await expect(service.deleteAccount({ username: '' })).resolves.toEqual({
        status: 400,
        body: { result: false, error: 'Username is required' },
      });
    });

    it('returns 404 when no user is deleted', async () => {
      const authRepository = createAuthRepository({
        deleteUser: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      });
      const service = createService(authRepository);

      await expect(service.deleteAccount({ username: 'missing@example.com' })).resolves.toEqual({
        status: 404,
        body: { result: false, error: 'User not found' },
      });
    });
  });

  describe('resetPassword', () => {
    it('returns 400 when username is missing', async () => {
      const authRepository = createAuthRepository();
      const service = createService(authRepository);

      await expect(service.resetPassword({ username: '', newPassword: 'secret' })).resolves.toEqual({
        status: 400,
        body: { result: false, error: 'Username is required' },
      });
    });

    it('returns 400 when newPassword is missing', async () => {
      const authRepository = createAuthRepository();
      const service = createService(authRepository);

      await expect(
        service.resetPassword({ username: 'user@example.com', newPassword: '' })
      ).resolves.toEqual({
        status: 400,
        body: { result: false, error: 'New password is required' },
      });
    });

    it('hashes and stores the new password', async () => {
      const authRepository = createAuthRepository();
      const service = createService(authRepository);

      await expect(
        service.resetPassword({ username: 'user@example.com', newPassword: 'new-secret' })
      ).resolves.toEqual({
        status: 200,
        body: { result: true, message: 'Password reset successfully' },
      });

      expect(authRepository.updatePassword).toHaveBeenCalledWith(
        'user@example.com',
        await hashPassword('new-secret')
      );
    });
  });
});
