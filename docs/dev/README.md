# Developer documentation

For building MazeDNS from source and working on the code. If you only want to
**deploy and run** MazeDNS, you don't need anything here — start at the
[operator docs](../README.md).

- **[Development](development.md)** — prerequisites, repo layout, `make` targets,
  running locally, tests, benchmarks, and how the two-image Dockerfile works.
- **[Architecture](architecture.md)** — components, the query pipeline, data model,
  auth, and the clustering/replication protocol.
- **[Latency audit](latency-audit.md)** — resolver hot-path performance analysis and
  the optimizations applied, with benchmarks.
- **[Improvement plan](improvement-plan.md)** — tracked issues and their fixes.
- **[Roadmap](roadmap.md)** — phased build plan.
