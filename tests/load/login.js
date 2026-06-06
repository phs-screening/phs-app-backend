import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const loginFailures = new Rate('login_failures');

const BASE_URL = __ENV.BASE_URL || 'http://localhost:3000/api';
const LOGIN_EMAIL = __ENV.LOGIN_EMAIL;
const LOGIN_PASSWORD = __ENV.LOGIN_PASSWORD;

export const options = {
  stages: [
    { duration: '30s', target: 10 },
    { duration: '30s', target: 25 },
    { duration: '30s', target: 50 },
    { duration: '30s', target: 100 },
    { duration: '30s', target: 0 },
],
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500'],
    login_failures: ['rate<0.01'],
  },
};

export default function () {
  if (!LOGIN_EMAIL || !LOGIN_PASSWORD) {
    throw new Error('Set LOGIN_EMAIL and LOGIN_PASSWORD when running this test.');
  }

  const res = http.post(
    `${BASE_URL}/handleLogin`,
    JSON.stringify({
      email: LOGIN_EMAIL,
      password: LOGIN_PASSWORD,
    }),
    {
      headers: {
        'Content-Type': 'application/json',
      },
    },
  );

  const ok = check(res, {
    'login returns 200': (r) => r.status === 200,
    'login returns result true': (r) => r.json('result') === true,
    'login returns token': (r) => Boolean(r.json('token')),
  });

  loginFailures.add(!ok);
  sleep(1);
}
