import acl, { ANY } from './index.js';
describe('A Seal', () => {
    afterEach(() => {
        acl.reset();
    });
    it('matches and returns an allow function', () => {
        let obj = acl.match(/\/foo/).for(['GET']);
        expect(obj.allow).toBeTypeOf('function');
        obj = acl.match(/\/foo/).for(['GET']);
        expect(obj.allow).toBeTypeOf('function');
        obj = acl.match(/^foo/).for(['GET']);
        expect(obj.allow).toBeTypeOf('function');
        obj = acl.match(/^foo/).for(['GET', 'POST']);
        expect(obj.allow).toBeTypeOf('function');
    });
    it('support labelling with scopes', () => {
        const rule = acl.match(/\/foo\/bar?/).for(['GET']).allow(['user']).as('READ_FOO');
        expect(rule.resource).toEqual(/\/foo\/bar?/);
        expect(rule.actions).toEqual(['GET']);
        expect(rule.roles).toEqual(['user']);
        expect(rule.scope).toEqual('READ_FOO');
    });
    it('creates access control rules', () => {
        acl.match(/\/foo\/bar?/).for(['GET']).allow(['user']);
        expect(acl.rules[0].resource).toEqual(/\/foo\/bar?/);
        expect(acl.rules[0].actions).toEqual(['GET']);
        expect(acl.rules[0].roles).toEqual(['user']);
        expect(acl.rules.length).toBe(1);
        acl.match(/\/foo\/bar$/).for(['GET', 'POST']).allow(['user', 'admin']);
        expect(acl.rules[1].resource).toEqual(/\/foo\/bar$/);
        expect(acl.rules[1].actions).toEqual(['GET', 'POST']);
        expect(acl.rules[1].roles).toEqual(['user', 'admin']);
        expect(acl.rules.length).toBe(2);
        //overwrite existing rule
        expect(() => {
            acl.match(/\/foo\/bar?/).for(['GET']).allow(['admin']);
        }).toThrowError();
    });
    it('checks if a role is allowed for a given resource and action', () => {
        let allowed;
        //RESOURCES
        //its a whitelist...
        allowed = acl.isAllowed('admin', '/resource', '*');
        expect(allowed).toBe(false);
        //add rules
        acl.match(/^\/resource/).for(['GET']).allow(['admin']);
        //test...
        allowed = acl.isAllowed('admin', '/resource', '*');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/resource/more', '*');
        expect(allowed).toBe(true);
        //ACTIONS
        //its a whitelist...
        allowed = acl.isAllowed('admin', '/actions', '*');
        expect(allowed).toBe(false);
        allowed = acl.isAllowed('admin', '/actions', '*');
        expect(allowed).toBe(false);
        //add rules
        acl.match(/\/actions-1/).for(['GET']).allow(['admin']);
        acl.match(/\/actions-1/).for(['POST']).allow(['admin']);
        acl.match(/\/actions-2/).for(['GET', 'POST']).allow(['admin']);
        acl.match(/\/actions-3/).for(['GET', 'POST']).allow(['admin']);
        //test...
        allowed = acl.isAllowed('admin', '/actions-1', '*');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/actions-1', 'GET');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/actions-1', 'POST');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/actions-1', 'BLAH');
        expect(allowed).toBe(false);
        allowed = acl.isAllowed('admin', '/actions-2', '*');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/actions-2', 'GET');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/actions-2', 'POST');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/actions-2', 'BLAH');
        expect(allowed).toBe(false);
        allowed = acl.isAllowed('admin', '/actions-3', '*');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/actions-3', 'GET');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/actions-3', 'POST');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/actions-3', 'BLAH');
        expect(allowed).toBe(false);
        //ROLES
        //its a whitelist...
        allowed = acl.isAllowed('admin', '/roles', 'admin');
        expect(allowed).toBe(false);
        allowed = acl.isAllowed('admin', '/roles', 'admin');
        expect(allowed).toBe(false);
        //add rules
        acl.match(/\/roles/).for(['GET']).allow([ANY]);
        acl.match(/\/roles/).for(['POST']).allow(['admin', 'user']);
        acl.match(/\/roles/).for(['DELETE']).allow(['hacker']);
        acl.match(/\/roles/).for(['PUT']).allow(['hacker', 'cleaner']);
        //test...
        allowed = acl.isAllowed('anon', '/roles', 'GET');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('anon', '/roles', 'FOO');
        expect(allowed).toBe(false);
        allowed = acl.isAllowed('admin', '/roles', 'GET');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('user', '/roles', 'GET');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('admin', '/roles', 'POST');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('user', '/roles', 'POST');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('hacker', '/roles', 'POST');
        expect(allowed).toBe(false);
        allowed = acl.isAllowed('hacker', '/roles', 'DELETE');
        expect(allowed).toBe(true);
        allowed = acl.isAllowed('cleaner', '/roles', 'PUT');
        expect(allowed).toBe(true);
    });
    it('authorizes requests with middleware', () => {
        const req = {
            method: 'GET',
        };
        const res = {};
        const next = vi.fn();
        acl.match(/\/public/).for(['GET']).allow(['foo', 'admin']);
        acl.match(/\/secret/).for(['GET']).allow(['admin']).as('SECRET_GETTER');
        const middleware = acl.middleware({ anon: 'foo' });
        req.path = `/public`;
        req.user = null;
        middleware(req, res, next);
        expect(req.scope).toBeUndefined();
        expect(next).toHaveBeenCalledTimes(1);
        expect(next.mock.lastCall.length).toBe(0);
        next.mockClear();
        req.user = { role: 'admin' };
        middleware(req, res, next);
        expect(req.scope).toBeUndefined();
        expect(next).toHaveBeenCalledTimes(1);
        expect(next.mock.lastCall.length).toBe(0);
        next.mockClear();
        req.path = `/secret`;
        req.user = { role: 'foo' };
        middleware(req, res, next);
        expect(req.scope).toBeUndefined();
        expect(next).toHaveBeenCalledTimes(1);
        expect(next.mock.lastCall[0].status).toBe(403);
        next.mockClear();
        req.user = { role: 'admin' };
        middleware(req, res, next);
        expect(req.scope).toBe('SECRET_GETTER');
        expect(next).toHaveBeenCalledTimes(1);
        expect(next.mock.lastCall.length).toBe(0);
        next.mockClear();
    });
});
