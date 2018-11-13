
describe('A Seal', () => {

    beforeEach(() => {
       this.acl = require('./index')(); 
    });

    afterEach(() => {
       this.acl.reset(); 
    });
    
    it('matches and returns a allow function', () => {
        const { acl } = this;

        let obj = acl.match('/foo').for('GET');
        expect(typeof obj.allow === 'function').toBe(true);

        obj = acl.match('/foo').for([ 'GET' ]);
        expect(typeof obj.allow === 'function').toBe(true);

        obj = acl.match(/^foo/).for([ 'GET' ]);
        expect(typeof obj.allow === 'function').toBe(true);

        obj = acl.match(/^foo/).for('GET', 'POST');
        expect(typeof obj.allow === 'function').toBe(true);
        
        const callWithBadResource = () => {
            acl.match(123);
        }
        expect(callWithBadResource).toThrow();
        
        const callWithBadActions = () => {
            acl.match(/ok/).for(undefined);
        }
        expect(callWithBadActions).toThrow();
    });
    
    it('support labelling with scopes', () => {
        var rule = this.acl
            .match('/foo/bar?').for('GET').allow('user').as('READ_FOO');
        
        expect(rule.resource).toEqual(/^\/foo\/bar\?$/);
        expect(rule.actions).toEqual([ 'GET' ]);
        expect(rule.roles).toEqual([ 'user' ]);
        expect(rule.scope).toEqual('READ_FOO');
        
    });
    
    it('creates access control rules', () => {
        var acl = this.acl;
        expect(acl._rules.length).toBe(0);
        
        acl.match('/foo/bar?').for('GET').allow('user');
        expect(acl._rules[0].resource).toEqual(/^\/foo\/bar\?$/);
        expect(acl._rules[0].actions).toEqual([ 'GET' ]);
        expect(acl._rules[0].roles).toEqual([ 'user' ]);
        expect(acl._rules.length).toBe(1);
        
        acl.match(/\/foo\/bar$/).for('GET', 'POST').allow([ 'user', 'admin' ]);
        expect(acl._rules[1].resource).toEqual(/\/foo\/bar$/);
        expect(acl._rules[1].actions).toEqual([ 'GET', 'POST' ]);
        expect(acl._rules[1].roles).toEqual([ 'user', 'admin' ]);
        expect(acl._rules.length).toBe(2);
        
        //overwrite existing rule
        acl.match('/foo/bar?').for('GET').allow('admin');
        expect(acl._rules[0].resource).toEqual(/^\/foo\/bar\?$/);
        expect(acl._rules[0].actions).toEqual([ 'GET' ]);
        expect(acl._rules[0].roles).toEqual([ 'admin' ]);
        expect(acl._rules.length).toBe(2);

        const callWithBadRole = () => {
            acl.match(/\/foo\/bar$/, [ 'GET', 'POST' ]).allow(true);
        }

        expect(callWithBadRole).toThrow();
    });
    
    it('checks if a role is allowed for a given resource and action', () => {
        const { acl } = this;
        let allowed;
        
        //RESOURCES

        //its a whitelist...
        allowed = acl.isAllowed('admin', '/string-resource', '*');
        expect(allowed).toBe(false);

        allowed = acl.isAllowed('admin', '/regex-resource', '*');
        expect(allowed).toBe(false);
        
        //add rules
        acl.match('/string-resource').for('GET').allow('admin');
        acl.match(/^\/regex-resource/).for('GET').allow('admin');
        
        //test...
        allowed = acl.isAllowed('admin', '/string-resource', '*');
        expect(allowed).toBe(true);

        allowed = acl.isAllowed('admin', '/regex-resource', '*');
        expect(allowed).toBe(true);
        
        allowed = acl.isAllowed('admin', '/string-resource/more', '*')
        expect(allowed).toBe(false);

        allowed = acl.isAllowed('admin', '/regex-resource/more', '*');
        expect(allowed).toBe(true);
        
        
        //ACTIONS

        //its a whitelist...
        allowed = acl.isAllowed('admin', '/actions', '*');
        expect(allowed).toBe(false);

        allowed = acl.isAllowed('admin', '/actions', '*');
        expect(allowed).toBe(false);

        //add rules
        acl.match('/actions-1').for('GET').allow('admin');
        acl.match('/actions-1').for('POST').allow('admin');
        acl.match('/actions-2').for([ 'GET', 'POST' ]).allow('admin');
        acl.match('/actions-3').for('GET', 'POST').allow('admin');
        
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
        acl.match('/roles').for('GET').allow(acl.ANY);
        acl.match('/roles').for('POST').allow([ 'admin', 'user' ]);
        acl.match('/roles').for('DELETE').allow([ 'hacker' ]);
        acl.match('/roles').for('PUT').allow('hacker', 'cleaner');
        
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

        //bad args
        const callWithBadRole = () => {
            allowed = acl.isAllowed(undefind, '/args', 'GET');
        }
        expect(callWithBadRole).toThrow();

        const callWithBadResource = () => {
            allowed = acl.isAllowed('admin', undefined, 'GET');
        }
        expect(callWithBadResource).toThrow();

        const callWithBadAction = () => {
            allowed = acl.isAllowed('admin', '/args', undefined);
        }
        expect(callWithBadAction).toThrow();
        
    });
    
    it('serializes a set or rules', () => {
        const acl = this.acl;
        let allowed;

        acl.match('/json').for('GET').allow('admin');
        acl.match('/json').for('POST').allow('admin');
        acl.match('/json').for([ 'GET', 'POST' ]).allow('admin');
        
        const json = acl.toJSON();
        this._rules = null;
        acl.fromJSON(json);

        allowed = acl.isAllowed('admin', '/json', '*');
        expect(allowed).toBe(true);

        allowed = acl.isAllowed('admin', '/json', 'GET');
        expect(allowed).toBe(true);

        allowed = acl.isAllowed('admin', '/json', 'POST');
        expect(allowed).toBe(true);

        allowed = acl.isAllowed('admin', '/json', 'BLAH');
        expect(allowed).toBe(false);
    });

    it('authorizes requests with middleware', () => {
        const { acl } = this;

        const req = {
            method: 'GET'
        };
        const res = {};
        const next = jasmine.createSpy('next');

        acl.match('/public').for('GET').allow('foo', 'admin');
        acl.match('/secret').for('GET').allow('admin').as('SECRET_GETTER');

        const middleware = acl.middleware({ anon: 'foo'});
        
        req.url = '/public';
        req.user = null;
        middleware(req, res, next);
        expect(req.scope).toBeUndefined();
        expect(next).toHaveBeenCalledTimes(1);
        expect(next.calls.mostRecent().args.length).toBe(0);
        next.calls.reset();
        
        req.user = { role: 'admin'};
        middleware(req, res, next);
        expect(req.scope).toBeUndefined();
        expect(next).toHaveBeenCalledTimes(1);
        expect(next.calls.mostRecent().args.length).toBe(0);
        next.calls.reset();

        req.url = '/secret';
        
        req.user = { role : 'foo' };
        middleware(req, res, next);
        expect(req.scope).toBeUndefined();
        expect(next).toHaveBeenCalledTimes(1);
        expect(next.calls.mostRecent().args[0].status).toBe(403);
        next.calls.reset();

        req.user = { role: 'admin'};
        middleware(req, res, next);
        expect(req.scope).toBe('SECRET_GETTER');
        expect(next).toHaveBeenCalledTimes(1);
        expect(next.calls.mostRecent().args.length).toBe(0);
        next.calls.reset();
    });
});