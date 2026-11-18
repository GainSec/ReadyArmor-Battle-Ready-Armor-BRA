# Documentation site

The technical atlas contains product guides, capabilities, architecture, operating traces, and source excerpts.
Its styles, screenshots, diagrams, scripts, search data, and document content are embedded in `index.html`.
The page works without a product server or an internet connection.

## Open the atlas

Open `docs/index.html` from the repository in a browser.
Use the left navigation to select a guide.
Use Search to find a feature, procedure, concept, or implementation symbol.
Use Control in Depth to examine each layer's boundary, activation, decisions, and code examples.
Select a source reference to read its code excerpt.
Select a screenshot to open the full image.
Use gallery categories to find related views.
Use the arrow buttons or arrow keys to change the view.
Select Actual size to inspect the image at its original resolution.
Press Escape to close the image.
Use the color control to select a light or dark theme.
Use the browser print command to print the full technical edition.

## Publish with GitHub Pages

The repository includes the generated HTML page in `docs/`.
Publish this checked-in page from the main branch:

1. Push the `main` branch to GitHub.
2. Open the repository's **Settings**.
3. Select **Pages**.
4. Under **Build and deployment**, set **Source** to **Deploy from a branch**.
5. Select the **main** branch and the **/docs** folder.
6. Select **Save**.
7. When publication completes, select **Visit site**.

GitHub Pages serves `docs/index.html` from the selected branch folder.
The `docs/.nojekyll` marker selects static file publication.
No custom repository Actions workflow is required.

## Update the atlas

The published HTML is already checked in.
Use the local builder after changing product documentation or the site profile:

```sh
python3 scripts/build_docs.py
```

The builder reads `docs/site.json` and the referenced Markdown chapters.
It refreshes the source file index from the configured implementation directories.
It embeds guides, original screenshots, diagrams, search data, and source excerpts in `docs/index.html`.
It also writes `docs/.nojekyll`.
Existing Markdown guides and screenshot files remain in `docs/`.
The build uses the Python standard library.

Update the guides when product behavior changes.
Update the site profile when capabilities, operating traces, or source locations change.
Build the atlas, include the generated HTML with those changes, and push the updated main branch.

## Verify the builder

```sh
python3 -m unittest discover -s scripts -p test_build_docs.py
```

The test checks offline links, unique anchors, embedded assets, escaped source content, and the `docs/` publication layout.
It also checks that the builder preserves its existing inputs.

## Share one file

Copy `docs/index.html` from the repository to another location or device.
Open the copied file in a browser.
The guides, screenshots, diagrams, search, operating traces, and source excerpts remain available in that file.
