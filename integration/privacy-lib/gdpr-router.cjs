'use strict';

const USER_POLICIES = Object.freeze({
  consent: 'consent.may_process_or_store',
  lawful: 'lawful.lawful_processing',
  information: 'information.information',
  access: 'access.access_response',
  rectification: 'rectification.rectification_response',
});
const REQUEST_POLICIES = Object.freeze({
  erasure: 'erasure', restriction: 'restriction', portability: 'portability',
  objection: 'objection', breach: 'breach', complaint: 'complaint',
});

/** Routes policy decisions only. Applications execute the returned action plans. */
class GdprRouter {
  constructor({ url = process.env.OPA_QUERY_URL || 'http://localhost:8181/v1/query',
    timeoutMs = 10000, fetchImpl = globalThis.fetch } = {}) {
    if (typeof fetchImpl !== 'function') throw new Error('Node.js 18+ is required');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('Invalid timeout');
    this.url = url;
    this.timeoutMs = timeoutMs;
    this.fetch = fetchImpl;
  }

  async query(expression, input) {
    const response = await this.fetch(this.url, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: `x := ${expression}`, input }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) throw new Error(`OPA query failed (HTTP ${response.status})`);
    const body = await response.json();
    if (!body || typeof body !== 'object' || Array.isArray(body) ||
        (body.result !== undefined && !Array.isArray(body.result))) {
      throw new Error('Invalid OPA response');
    }
    return body.result?.[0]?.x ?? null;
  }

  async route(policy, input, userId = null) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new TypeError('input must be a JSON object');
    }
    if (Object.hasOwn(USER_POLICIES, policy)) {
      if (typeof userId !== 'string' || userId.length === 0) {
        throw new TypeError('userId must be a nonempty string');
      }
      // JSON encoding prevents a user ID from introducing Rego expressions.
      const value = await this.query(`data.${USER_POLICIES[policy]}(${JSON.stringify(userId)})`, input);
      return value ?? (['consent', 'lawful'].includes(policy) ? false : {});
    }
    if (!Object.hasOwn(REQUEST_POLICIES, policy)) throw new Error(`Unknown policy: ${policy}`);
    const prefix = `data.${REQUEST_POLICIES[policy]}`;
    const decision = await this.query(`${prefix}.decision`, input);
    const justification = await this.query(`${prefix}.justification`, input);
    const actions = await this.query(`${prefix}.actions`, input);
    return {
      decision: decision ?? (policy === 'breach' ? 'no_notify' : 'reject'),
      justification: justification ?? [], actions: actions ?? {},
    };
  }
}

module.exports = { GdprRouter };
