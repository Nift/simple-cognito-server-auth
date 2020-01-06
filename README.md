# simple-cognito-server-auth

A simple library I made to easily allow:

- Easy server side authentication of Cognito users. Basically, the JWT token obtained when logging in as an Cognito user is verified against the user pool and region you decide
- Easily migrate users from an existing user store such as Firebase or Gigya, by allowing to easily "silently" create users in Cognito. "Silently" means the email is transferred and confirmed, but no email is actually send to the user about this migration. I only transfer the email attribute when creating silently.

I use it succesfully in production but migrating from Firebase, but your milage might vary.

# Contributing

You are welcome to fork or suggest edits to the code through PRs and creating issues.

# License

The MIT License (MIT)

Copyright (c) 2015 Chris Kibble

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
