# A Seal

Access Control List (ACL) library for Node.JS

<img src="mark-spencer.jpg" width="500">

## Install
```
npm install a-seal
```

## Usage

Setting up an access control list consists of creating a list of rules. Each rule is composed with the process:

* **match** a resource **for** action(s) then **allow** role(s).

The **isAllowed()** function can then by used to check if a user, given their role, is authorized to access a resource.
A Seal creates a white-list of rules, so *isAllowed()* will return `false`, unless an exception has been created.

```javascript

// Create an acl instance
const acl = require('a-seal')();

// Compose rules of a 'resource', 'actions' and 'roles' using...
// `match`, `for` and `allow` respectively:
acl.match('/protected-path').for('GET').allow('user', 'admin');
acl.match(/^\/protected-path/).for('GET', 'POST').allow('admin');

// Optionally label the rule with a "scope" using an `as` clause

acl.match(/^\/protected-path/).for('GET', 'POST').allow('admin').as('PROTECTED_WRITE');

//use `isAllowed(role, resource, action)`...
//to determine if a request is allowed to access the resource with a given action:
acl.isAllowed('admin', '/protected-path', 'POST') //true
acl.isAllowed('user', '/protected-path', 'POST') //false

//A Seal creates a white-list of rules, so:
acl.isAllowed('admin', '/protected-path', 'DELETE') //false
```

<small>Although the examples on this page use HTTP, there is nothing HTTP specific about *A Seal*.</small>

### Middleware

A Seal can be used as [Express](http://expressjs.com/) middleware to authorize requests after 
authentication with tools such as [Passport](http://passportjs.org/):

```javascript
//authentication with Passport
app.use(passport.authenticate('local'));

const acl = require('a-seal')();
acl.match('/protected-path').for('GET').allow('user');
acl.match('/protected-path').for('GET', 'POST').allow('admin').as('PROTECTED_WRITE');

app.use(acl.middleware());

app.use('/protected-path', (req, res, next) => {
    // the matched rule's "scope" label will be added to the request
    res.send(`<p>Authorized ok with scope: ${req.scope}</p>`);
});

app.use((err, req, res) => {
    if(err.status === 403) {
        res.send('<p>Authorization failed</p>');
    }
});
```

## API

### match(resource)

Begins a matching context given a resource to match. If the resource is a string, an exact, case-sensitive 
match is performed.

Returns: `object` (matchingContext)

#### Params
##### resource

Type: `string` | `RegExp`

#### Examples:

```javascript
acl.match('/my-path') //exact string match
acl.match(/^\/my-path/) //match with regex (starting with /my-path)
```

### matchingContext.for(actions)

Returns: object (matchingContext)

Completes a matching context by adding one or more actions. When authorizing HTTP requests, for example, actions will 
typically be HTTP methods.

Returns `object` (matchingContext)

#### Params
##### actions

Type: `...string` | `Array`

A list of permitted actions as an array of strings or a list of strings as arguments.

#### Examples

```javascript
acl.match('/my-path').for(['GET', 'POST' ]);
acl.match('/my-path').for('GET', 'POST');

//match any action
acl.match('/my-path').for(acl.ANY);
```

### matchingContext.allow(roles)

Adds a new ACL rule by adding one or more roles to a matching context.

Returns: `object` (rule)

#### Params
##### roles

Type: `...string` | `Array`

A list of permitted roles as an array of strings or a list of strings as arguments.

#### Examples

```javascript
acl.match('/my-path').for('GET').allow([ 'user', 'anon' ]);
acl.match('/my-path').for('GET').allow('user', 'anon');
acl.match('/my-path').for('GET').allow(...myRoles);

//match any role
acl.match('/public').for('GET').allow(acl.ANY);
```

### rule.as(scope)

Labels this rule with a custom "scope"

#### Params

##### scope

Type: `string`

#### Examples

```javascript
acl.match('/my-path').for('POST').allow('user').as('user_create');
```

### isAllowed(role, resource, action)

Determines if a given role is authorized to access a given resource with a given action.

#### Params
##### role

Type: `string`

##### resource 

Type: `string`

##### action

Type: `string`

#### Examples:

```javascript
acl.isAllowed('admin', '/my-path', 'GET');
```

### middleware(opts)

Returns an Express middleware function that accepts `req`, `res` and `next` arguments.

The role is checked against the ACL ruleset using the `isAllowed` function. If it returns `false`, it creates a 403
error; if true the routing chain is allowed to continue.

If `req.role` is not defined, and a custom anonymous role is not provided, the role value will default to `guest`. 

#### Params
##### opts.anon

Type: `string`

The default role for users (anonymous users). This defaults to `'guest'`.

```javascript
app.use(acl.middleware({ anon: 'anonymous'});
```

## License

MIT © Phil Mander
