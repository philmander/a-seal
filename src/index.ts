import { Request, Response, NextFunction } from 'express'

export const ANY = '*'
export const ANON_USER = {
  role: 'guest'
}

type Rule = {
  resource: RegExp
  actions: string[]
  roles: string[]
  scope?: string
}

export type MiddlewareOpts = {
  anon?: string
}

export interface AuthenticatedRequest extends Request {
  user?: { role: string } | null
  scope?: string
}

export class Acl {

  private _rules: Rule[] = []

  private findRule(role: string, resource: string, action: string): Rule | null {
    return this._rules.reverse().find(rule => {
      const matchResource = rule.resource.test(resource)
      const matchAction = action === '*' || rule.actions.includes(action)
      const matchUser = matchResource && matchAction && (rule.roles.includes('*') || rule.roles.includes(role))

      return matchUser
    }) || null
  }

  get rules(): Rule[] {
    return this._rules
  }

  /**
   * Add a new rule, starting with the resource + action to match
   * @param resource
   * @returns {{onlyAllow: onlyAllow}}
   */
  match(resource: RegExp) {
    return {
      for: (actions: string[]) => {
        return {
          allow: (roles: string[]) => {
            //find existing rule
            let existingRule = this._rules.find(rule =>
              rule.resource.source === resource.source && rule.actions.sort().toString() === actions.sort().toString()
            )
            if (existingRule) {
              throw new Error('Rules have already been defined for this resource/action combination')
            }

            const rule: Rule = { resource, actions, roles }
            this._rules.push(rule)

            return {
              as: (scope: string) => {
                rule.scope = scope
                return rule
              }
            }
          }
        }
      }
    }
  }

  /**
   * Loops through the acls in order added looking for a resource pattern match.
   * Grants permission if the role is found
   * @param role
   * @param resource
   * @param action
   * @returns {boolean}
   */
  public isAllowed(role: string, resource: string, action: string): boolean {
    return !!this.findRule(role, resource, action)
  }

  /**
   * Express middleware
   * @param {*} opts 
   */
  middleware(opts: MiddlewareOpts) {
    return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
      const user = req.user ?? (typeof opts?.anon === 'string' ? { role: opts.anon } : ANON_USER)
      if (this.isAllowed(user.role, req.path, req.method)) {
        const rule = this.findRule(user.role, req.path, req.method)
        if (rule && rule.scope) {
          req.scope = rule.scope
        }
        return next()
      } else {
        const msgAndStatus: [string, number] = user.role === opts?.anon || user.role === ANON_USER.role ?
          [ `User is not authenticated to access the resource "${req.path}"`, 401 ] :
          [ `User "${user.role}" is not authorized to "${req.method}" to the resource "${req.path}"`, 403 ]
        const err = new HttpError(...msgAndStatus)
        return next(err)
      }
    }
  }

  /**
   * Clear all rules
   */
  reset() {
    this._rules = []
  }
}

class HttpError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

const acl = new Acl()
export default acl