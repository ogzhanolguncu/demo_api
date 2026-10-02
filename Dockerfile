FROM node:22-alpine
RUN apk add --no-cache git curl
RUN git clone https://github.com/octocat/Hello-World /hw          # stderr, succeeds
RUN npm install inflight@1.0.6                                    # stderr warning, succeeds
RUN echo 'const x: number = "a";' > bad.ts && npx -y -p typescript tsc bad.ts   # stdout, fails
