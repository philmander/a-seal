describe('Specs for A Seal', function() {

    beforeEach(function() {
       this.acl = require('../src/index')(); 
    });
    afterEach(function () {
       this.acl.reset(); 
    });
    
    
    it('matches and returns a thenAllow function', function() {
        
        var acl = this.acl;

        var obj = acl.match('/foo').for('GET');
        expect(typeof obj.thenAllow === 'function').toBe(true);

        obj = acl.match('/foo').for([ 'GET' ]);
        expect(typeof obj.thenAllow === 'function').toBe(true);

        obj = acl.match(/^foo/).for([ 'GET' ]);
        expect(typeof obj.thenAllow === 'function').toBe(true);

        obj = acl.match(/^foo/).for('GET', 'POST');
        expect(typeof obj.thenAllow === 'function').toBe(true);
        
        function callWithBadResource() {
            acl.match(123);
        }
        expect(callWithBadResource).toThrow();
        
        function callWithBadActions() {
            acl.match(/ok/).for(undefined);
        }
        expect(callWithBadActions).toThrow();
    });
    
    it('support chaining rules', function () {

        var acl = this.acl
            .match('/foo/bar?').for('GET').thenAllow('user')
            .match(/\/foo\/bar$/).for('GET', 'POST').thenAllow([ 'user', 'admin' ]);
        
        expect(acl._rules[0].resource).toEqual(/^\/foo\/bar\?$/);
        expect(acl._rules[0].actions).toEqual([ 'GET' ]);
        expect(acl._rules[0].roles).toEqual([ 'user' ]);
        
        expect(acl._rules[1].resource).toEqual(/\/foo\/bar$/);
        expect(acl._rules[1].actions).toEqual([ 'GET', 'POST' ]);
        expect(acl._rules[1].roles).toEqual([ 'user', 'admin' ]);
    });
    
    it('creates access control rules', function () {
        var acl = this.acl;
        expect(acl._rules.length).toBe(0);
        
        acl.match('/foo/bar?').for('GET').thenAllow('user');
        expect(acl._rules[0].resource).toEqual(/^\/foo\/bar\?$/);
        expect(acl._rules[0].actions).toEqual([ 'GET' ]);
        expect(acl._rules[0].roles).toEqual([ 'user' ]);
        expect(acl._rules.length).toBe(1);
        
        acl.match(/\/foo\/bar$/).for('GET', 'POST').thenAllow([ 'user', 'admin' ]);
        expect(acl._rules[1].resource).toEqual(/\/foo\/bar$/);
        expect(acl._rules[1].actions).toEqual([ 'GET', 'POST' ]);
        expect(acl._rules[1].roles).toEqual([ 'user', 'admin' ]);
        expect(acl._rules.length).toBe(2);
        
        //overwrite existing rule
        acl.match('/foo/bar?').for('GET').thenAllow('admin');
        expect(acl._rules[0].resource).toEqual(/^\/foo\/bar\?$/);
        expect(acl._rules[0].actions).toEqual([ 'GET' ]);
        expect(acl._rules[0].roles).toEqual([ 'admin' ]);
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
        acl.match('/string-resource').for('GET').thenAllow('admin');
        acl.match(/^\/regex-resource/).for('GET').thenAllow('admin');
        
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
        acl.match('/actions-1').for('GET').thenAllow('admin');
        acl.match('/actions-1').for('POST').thenAllow('admin');
        acl.match('/actions-2').for([ 'GET', 'POST' ]).thenAllow('admin');
        acl.match('/actions-3').for('GET', 'POST').thenAllow('admin');
        
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
        acl.match('/roles').for('GET').thenAllow(acl.ANY);
        acl.match('/roles').for('POST').thenAllow([ 'admin', 'user' ]);
        acl.match('/roles').for('DELETE').thenAllow([ 'hacker' ]);
        acl.match('/roles').for('PUT').thenAllow('hacker', 'cleaner');
        
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

        acl.match('/json').for('GET').thenAllow('admin');
        acl.match('/json').for('POST').thenAllow('admin');
        acl.match('/json').for([ 'GET', 'POST' ]).thenAllow('admin');
        
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