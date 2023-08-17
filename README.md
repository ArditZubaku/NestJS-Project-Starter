# NestJS-Project-Starter

<p>
  <a href="https://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>

  <p>A progressive <a href="https://nodejs.org" target="_blank">Node.js</a> framework for building efficient and scalable server-side applications.</p>

## Description

#### [Nest](https://github.com/nestjs/nest) framework TypeScript starter repository with Prisma, auth using Passport strategies, JwtGuard, RtGuard, decorators, refreshToken and accessToken, all set up.

## Installation

```bash
yarn install
```

## Setting up env variables

```bash
mv .env.test .env
```

Then, change the env variables as per your wish.

## Database setup

```bash
yarn dev:db:start
```

## Running the app

```bash
# development
yarn run start

# watch mode
yarn run start:dev

# production mode
yarn run start:prod
```

## Test

```bash
# unit tests
yarn run test

# e2e tests
yarn run test:e2e

# test coverage
yarn run test:cov
```
