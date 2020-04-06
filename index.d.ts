declare module 'a-seal' {
    import { RequestHandler } from 'express';

    function e(): Acl;

    export = e;

    class Acl {
        public match(resource: string | RegExp): ForContext;
        public isAllowed(role: string, resource: string, action: string): boolean;
        public middleware(opts: { anon: string }): RequestHandler;
        public toJSON(): string;
        public fromJSON(): void;
        public reset(): void;
    }

    interface ForContext {
        for(...actions: string[]): AllowContext;
        for(actions: string[]): AllowContext;
    }

    interface AllowContext {
        allow(...roles: string[]): AsContext;
        allow(roles: string[]): AsContext;
    }

    interface AsContext {
        as(scope: string): Rule;
    }

    interface Rule {
        scope: string;
        resource: RegExp;
        actions: string[];
        roles: string[];
    }
}

