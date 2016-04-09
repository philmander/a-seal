describe('Specs for A Seal', function() {

    beforeEach(function() {
       this.acl = require('../src/index')(); 
    });
    
    it('matches and returns a thenAllow function', function() {
        
        var acl = this.acl;

        var obj = acl.match('/foo', 'GET');
        expect(typeof obj.thenAllow === 'function').toBe(true);

        obj = acl.match('/foo', [ 'GET' ]);
        expect(typeof obj.thenAllow === 'function').toBe(true);

        obj = acl.match(/^foo/, [ 'GET' ]);
        expect(typeof obj.thenAllow === 'function').toBe(true);
        
        function callWithBadResource() {
            acl.match(123, 'GET');
        }
        expect(callWithBadResource).toThrow();
        
        function callWithBadActions() {
            acl.match(/ok/, undefined);
        }
        expect(callWithBadActions).toThrow();
    });
    
    it('creates access control rules', function () {
        var acl = this.acl;
        var rule;
        expect(acl._rules.length).toBe(0);
        
        rule = acl.match('/foo/bar?', 'GET').thenAllow('user');
        expect(rule.resource).toEqual(/^\/foo\/bar\?$/);
        expect(rule.actions).toEqual([ 'GET' ]);
        expect(rule.roles).toEqual([ 'user' ]);
        expect(acl._rules.length).toBe(1);
        
        rule = acl.match(/\/foo\/bar$/, [ 'GET', 'POST' ]).thenAllow([ 'user', 'admin' ]);
        expect(rule.resource).toEqual(/\/foo\/bar$/);
        expect(rule.actions).toEqual([ 'GET', 'POST' ]);
        expect(rule.roles).toEqual([ 'user', 'admin' ]);
        expect(acl._rules.length).toBe(2);
        
        //overwrite existing rule
        rule = acl.match('/foo/bar?', 'GET').thenAllow('admin');
        expect(rule.resource).toEqual(/^\/foo\/bar\?$/);
        expect(rule.actions).toEqual([ 'GET' ]);
        expect(rule.roles).toEqual([ 'admin' ]);
        expect(acl._rules.length).toBe(2);

        function callWithBadRole() {
            acl.match(/\/foo\/bar$/, [ 'GET', 'POST' ]).thenAllow(true);
        }

        expect(callWithBadRole).toThrow();
    });
    
    it('checks if a role is allowed for a given resource and action', function () {
        
        var acl = this.acl;
        var allowed;
        
        //RESOURCES

        //its a whitelist...
        allowed = acl.isAllowed('admin', '/string-resource', '*');
        expect(allowed).toBe(false);

        allowed = acl.isAllowed('admin', '/regex-resource', '*');
        expect(allowed).toBe(false);
        
        //add rules
        acl.match('/string-resource', 'GET').thenAllow('admin');
        acl.match(/^\/regex-resource/, 'GET').thenAllow('admin');
        
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
        acl.match('/actions-1', 'GET').thenAllow('admin');
        acl.match('/actions-1', 'POST').thenAllow('admin');
        acl.match('/actions-2', [ 'GET', 'POST' ]).thenAllow('admin');
        
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
        
        
        //ROLES

        //its a whitelist...
        allowed = acl.isAllowed('admin', '/roles', 'admin');
        expect(allowed).toBe(false);

        allowed = acl.isAllowed('admin', '/roles', 'admin');
        expect(allowed).toBe(false);

        //add rules
        acl.match('/roles', 'GET').thenAllow('*');
        acl.match('/roles', 'POST').thenAllow([ 'admin', 'user' ]);
        acl.match('/roles', 'DELETE').thenAllow([ 'hacker' ]);
        
        //test...

        allowed = acl.isAllowed('anon', '/roles', 'GET');
        expect(allowed).toBe(true);

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


        //bad args
        function callWithBadRole() {
            allowed = acl.isAllowed(undefind, '/args', 'GET');
        }
        expect(callWithBadRole).toThrow();

        function callWithBadResource() {
            allowed = acl.isAllowed('admin', undefined, 'GET');
        }
        expect(callWithBadResource).toThrow();

        function callWithBadAction() {
            allowed = acl.isAllowed('admin', '/args', undefined);
        }
        expect(callWithBadAction).toThrow();
        
    });
    
    it('serializes a set or rules', function () {
       
        var acl = this.acl;
        var allowed;

        acl.match('/json', 'GET').thenAllow('admin');
        acl.match('/json', 'POST').thenAllow('admin');
        acl.match('/json', [ 'GET', 'POST' ]).thenAllow('admin');
        
        var json = acl.toJSON();
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
});