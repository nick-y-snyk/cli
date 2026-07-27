import { createProjectFromFixture } from '../../util/createProject';
import { runSnykCLI } from '../../util/runSnykCLI';

jest.setTimeout(1000 * 60);

// `--include-component-metadata` makes the python plugin forward the flag to
// snyk-poetry-lockfile-parser, which reads the per-package hashes already in
// poetry.lock and surfaces them as `hash:<algorithm>` labels on the dep-graph
// nodes. Like npm (and unlike maven) there is nothing to resolve first — the
// hashes live in the lockfile — so this fixture needs no `poetry install`.
//
// Note the asymmetry with npm: for PyPI-sourced packages poetry.lock records no
// download URL, so only `hash:` labels appear here, not `distribution:url`
// (those are emitted only for `url`/`legacy` sources — see
// snyk-poetry-lockfile-parser/docs/component-metadata.md). This test therefore
// asserts hash labels only.
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

  const fixture = 'poetry-include-component-metadata';

  it('attaches hash labels with the flag', async () => {
    const project = await createProjectFromFixture(fixture);

    const { code, stdout } = await runSnykCLI(
      'test --include-component-metadata --print-graph --file=poetry.lock',
      { cwd: project.path() },
    );

    expect(code).toEqual(0);
    const graphs = parseDepGraphs(stdout);
    expect(graphs).toHaveLength(1);
    expect(labelKeys(graphs[0].graph, 'hash:').length).toBeGreaterThan(0);
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
  });
});
