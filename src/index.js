const { parse: parseUrl } = require('url');

class Acl {

    constructor() {
        this.ANY = '*';
        this.ANON_USER = {
            role: 'guest'
        };
        
        this._rules = [];
    }

    _findRule(role, resource, action) {
        for(let i = this._rules.length - 1; i >= 0; i--) {
            const rule = this._rules[i];

            //test if regex
            const matchResource = rule.resource.test(resource);

            //string star will match any otherwise find match in actions array
            const matchAction = action === this.ANY || rule.actions.indexOf(action) > -1;

            //if the resource + action is match then allow or deny, given the role
            const matchUser = matchResource && matchAction && 
                (rule.roles.indexOf(this.ANY) > -1 || rule.roles.indexOf(role) > -1);
            if(matchUser) {
                return rule;
            }
        }
        return null;
    }

    /**
     * Add a new rule, starting with the resource + action to match
     * @param resource
     * @returns {{onlyAllow: onlyAllow}}
     */
    match(resource) {
        function argsAreStrings(args) {
            if(Array.isArray(args[0])) {
                args = args[0];
            }
            
            return Array.prototype.slice.call(args).every(val => typeof val === 'string');
        }

        //validate
        if(typeof resource === 'string') {
            resource = new RegExp('^' + resource.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&") + '$');
        }
        
        //normalize
        if(!(resource instanceof RegExp)) {
            throw new Error('Cannot do acl match, resources must be a string or regex');
        }

        return {
            for: function(actions) {
                //validate
                if(!Array.isArray(actions) && !argsAreStrings(arguments)) {
                    throw new Error('Cannot add acl rule, actions must be strings or an array');
                }

                //normalize
                if(!Array.isArray(actions)) {
                    actions = Array.prototype.slice.call(arguments);
                }

                return {
                    allow: function(roles) {
                        //validate
                        if(!Array.isArray(roles) && !argsAreStrings(arguments)) {
                            throw new Error('Cannot add acl rule, roles must be strings or an array');
                        }

                        //normalize
                        if(!Array.isArray(roles)) {
                            roles = Array.prototype.slice.call(arguments);
                        }

                        //find existing rule
                        const rule = this._rules.find(rule => 
                            rule.resource.source === resource.source && rule.actions.sort().toString() === actions.sort().toString()
                        ) || { _new: true };

                        //create or update
                        rule.resource = resource;
                        rule.actions = actions;
                        rule.roles = roles;

                        //add if new
                        if(rule._new) {
                            delete rule._new;
                            this._rules.push(rule);
                        }

                        return {
                            as: function(scope) {
                                rule.scope = scope;
                                return rule;
                            }.bind(this)
                        }
                    }.bind(this)
                }
            }.bind(this)
        };
    }

    /**
     * Loops through the acls in order added looking for a resource pattern match.
     * Grants permission if the role is found
     * @param role
     * @param resource
     * @param action
     * @returns {boolean}
     */
    isAllowed(role, resource, action) {
        //check args
        const argNames = [ 'role', 'resource', 'action'];
        for(let i = 0; i < argNames.length; i++) {
            if(typeof arguments[i] !== 'string') {
                const msg = `Cannot check permission with this ${argNames[i]}. It should be a string, but it is a: ${typeof argNames[i]}`;
                throw new Error(msg);
            }    
        }

        return !!this._findRule(role, resource, action);
    }

    /**
     * Express middleware
     * @param {*} opts 
     */
    middleware(opts) {
        return function(req, res, next) {
            const user = req.user || (opts && typeof opts.anon === 'string' ? { role: opts.anon } : this.ANON_USER);
            const { pathname: urlPath } = parseUrl(req.url);
            if(this.isAllowed(user.role, urlPath, req.method)) {
                const { scope } = this._findRule(user.role, urlPath, req.method); 
                if(scope) {
                    req.scope = scope;
                }
                return next();
            } else {
                const err = new Error(`User "${req.user}" is not authorized to "${req.method}" to the resource "${urlPath}"`);
                err.status = 403;
                return next(err);
            }
        }.bind(this);
    }

    /**
     * Serializes this ACL instance
     */
    toJSON() {
        //temp patch regex tojson method
        const orignalRegexToJson = RegExp.prototype.toJSON;
        RegExp.prototype.toJSON = RegExp.prototype.toString;

        const serialized = JSON.stringify(this._rules);
        RegExp.prototype.toJSON = orignalRegexToJson;
        return serialized;
    }

    /**
     * Deserializes from JSON that was generated by toJSON
     * @param rules
     */
    fromJSON(rules) {
        rules = JSON.parse(rules);

        const isRegexPattern = new RegExp('^\/(.*)\/$');
        rules = rules.map(function (rule) {
            const regex = isRegexPattern.exec(rule.resource);
            rule.resource = new RegExp(regex[1]);
            return rule;
        });

        this._rules = rules;
    }

    /**
     * Clear all rules
     */
    reset() {
        this._rules = [];
    }
}

module.exports = () => new Acl();