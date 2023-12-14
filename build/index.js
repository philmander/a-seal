export const ANY = '*';
export const ANON_USER = {
    role: 'guest'
};
export class Acl {
    _rules = [];
    findRule(role, resource, action) {
        return this._rules.reverse().find(rule => {
            const matchResource = rule.resource.test(resource);
            const matchAction = action === '*' || rule.actions.includes(action);
            const matchUser = matchResource && matchAction && (rule.roles.includes('*') || rule.roles.includes(role));
            return matchUser;
        }) || null;
    }
    get rules() {
        return this._rules;
    }
    /**
     * Add a new rule, starting with the resource + action to match
     * @param resource
     * @returns {{onlyAllow: onlyAllow}}
     */
    match(resource) {
        return {
            for: (actions) => {
                return {
                    allow: (roles) => {
                        //find existing rule
                        let existingRule = this._rules.find(rule => rule.resource.source === resource.source && rule.actions.sort().toString() === actions.sort().toString());
                        if (existingRule) {
                            throw new Error('Rules have already been defined for this resource/action combination');
                        }
                        const rule = { resource, actions, roles };
                        this._rules.push(rule);
                        return {
                            as: (scope) => {
                                rule.scope = scope;
                                return rule;
                            }
                        };
                    }
                };
            }
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
        return !!this.findRule(role, resource, action);
    }
    /**
     * Express middleware
     * @param {*} opts
     */
    middleware(opts) {
        return (req, res, next) => {
            const user = req.user || (opts && typeof opts.anon === 'string' ? { role: opts.anon } : ANON_USER);
            const { pathname: urlPath } = new URL(req.url);
            if (this.isAllowed(user.role, urlPath, req.method)) {
                const rule = this.findRule(user.role, urlPath, req.method);
                if (rule && rule.scope) {
                    req.scope = rule.scope;
                }
                return next();
            }
            else {
                const err = new HttpError(`User "${user.role}" is not authorized to "${req.method}" to the resource "${urlPath}"`, 403);
                return next(err);
            }
        };
    }
    /**
     * Clear all rules
     */
    reset() {
        this._rules = [];
    }
}
class HttpError extends Error {
    status;
    constructor(message, status) {
        super(message);
        this.status = status;
    }
}
const acl = new Acl();
export default acl;
