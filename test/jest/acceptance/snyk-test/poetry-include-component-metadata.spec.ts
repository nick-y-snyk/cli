import { createProjectFromFixture } from '../../util/createProject';
import { runSnykCLI } from '../../util/runSnykCLI';

jest.setTimeout(1000 * 60);

// `--include-component-metadata` makes the python plugin forward the flag to
// snyk-poetry-lockfile-parser, which reads the per-package hashes already in
// poetry.lock and surfaces them as `hash:<algorithm>` labels on the dep-graph
// nodes. Like npm (and unlike maven) there is nothing to resolve first — the
// hashes live in the lockfile — so this fixture needs no `poetry install`.
//
// Note the difference from npm: poetry.lock records no artifact *download* URL,
// so `distribution:url` here is the PEP 503 project page for the package with a
// `#<filename>` fragment naming the file whose hash is reported — provenance
// rather than a fetch target. For PyPI-sourced deps (no `[package.source]`) that
// root is pypi.org; private-index (`legacy`) deps use their recorded root. See
// snyk-poetry-lockfile-parser/docs/component-metadata.md.
describe('`snyk test --include-component-metadata` (poetry)', () => {
  interface PrintedGraph {
    target: string;
    graph: any;
  }

  const parseDepGraphs = (printGraphStdout: string): PrintedGraph[] =>
    printGraphStdout
      .split('DepGraph end')
      .filter((block) => block.includes('DepGraph data:'))
      .map((block) => ({
        graph: JSON.parse(
          block.split('DepGraph data:')[1].split('DepGraph target:')[0],
        ),
        target: block.split('DepGraph target:')[1].trim(),
      }));

  const labelKeys = (graph: any, prefix: string): string[] =>
    graph.graph.nodes
      .flatMap((node) => Object.keys(node.info?.labels ?? {}))
      .filter((key) => key.startsWith(prefix));

  const labelValues = (graph: any, key: string): string[] =>
    graph.graph.nodes
      .map((node) => node.info?.labels?.[key])
      .filter((value): value is string => Boolean(value));

  const fixture = 'poetry-include-component-metadata';

  it('attaches hash and distribution:url labels with the flag', async () => {
    const project = await createProjectFromFixture(fixture);

    const { code, stdout } = await runSnykCLI(
      'test --include-component-metadata --print-graph --file=poetry.lock',
      { cwd: project.path() },
    );

    expect(code).toEqual(0);
    const graphs = parseDepGraphs(stdout);
    expect(graphs).toHaveLength(1);
    expect(labelKeys(graphs[0].graph, 'hash:').length).toBeGreaterThan(0);

    // The fixture's deps come from PyPI, so each carries a pypi.org project-page
    // URL whose fragment names the artifact the sibling hash describes.
    const urls = labelValues(graphs[0].graph, 'distribution:url');
    expect(urls.length).toBeGreaterThan(0);
    for (const url of urls) {
      expect(url).toMatch(/^https:\/\/pypi\.org\/simple\/[^/]+\/#.+$/);
    }
  });

  // Control: without the flag the same project must not produce the labels,
  // proving they are driven by `--include-component-metadata`.
  it('does not attach the labels without the flag', async () => {
    const project = await createProjectFromFixture(fixture);

    const { code, stdout } = await runSnykCLI(
      'test --print-graph --file=poetry.lock',
      { cwd: project.path() },
    );

    expect(code).toEqual(0);
    const graphs = parseDepGraphs(stdout);
    expect(graphs).toHaveLength(1);
    expect(labelKeys(graphs[0].graph, 'hash:')).toHaveLength(0);
    expect(labelKeys(graphs[0].graph, 'distribution:url')).toHaveLength(0);
  });
});
