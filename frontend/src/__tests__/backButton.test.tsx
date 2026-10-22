import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import BackButton from '../components/BackButton';

describe('BackButton', () => {
  it('uses the safe fallback when there is no in-app history entry', async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={['/documents/doc_1']}>
        <Routes>
          <Route
            path="/documents/doc_1"
            element={<BackButton fallback="/documents" label="My documents" />}
          />
          <Route path="/documents" element={<div>Documents fallback</div>} />
        </Routes>
      </MemoryRouter>,
    );

    await user.click(screen.getByRole('button', { name: 'My documents' }));

    expect(screen.getByText('Documents fallback')).toBeInTheDocument();
  });
});
