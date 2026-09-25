import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import App from './App'

// Render smoke test: the fixtures load through import.meta.glob, the gallery
// shows them, and opening the run with unobserved stages surfaces the
// "UNKNOWN ≠ safe" doctrine banner (proving the tri-state is not collapsed).
describe('<App /> smoke', () => {
  it('renders the gallery with the bundled fixture runs', () => {
    render(<App />)
    expect(screen.getByText(/Mission Control/)).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'run-cross-user-bac-vulnerable' }),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { name: 'run-tool-route-hijack-skipped' }),
    ).toBeInTheDocument()
  })

  it('opens a run with unknown stages and shows the UNKNOWN ≠ safe doctrine', () => {
    render(<App />)
    // Doctrine banner text is not on the gallery.
    expect(screen.queryByText(/Absence of evidence is not evidence/)).toBeNull()

    fireEvent.click(
      screen.getByRole('heading', { name: 'run-tool-route-hijack-skipped' }),
    )

    // Now on the run page: the banner and the funnel must be present.
    expect(screen.getByText(/Absence of evidence is not evidence/)).toBeInTheDocument()
    expect(screen.getByText(/Kill-chain funnel/)).toBeInTheDocument()
  })

  it('renders a clean controlled run without the not-safe banner', () => {
    render(<App />)
    fireEvent.click(
      screen.getByRole('heading', { name: 'run-cross-user-bac-protected' }),
    )
    expect(screen.getByText(/Kill-chain funnel/)).toBeInTheDocument()
    // No unknown stages -> no "UNKNOWN ≠ safe" caveat for this run.
    expect(screen.queryByText(/Absence of evidence is not evidence/)).toBeNull()
  })
})
