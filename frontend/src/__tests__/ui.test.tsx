import { useRef, useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import Dialog from '../components/Dialog';
import Menu from '../components/Menu';
import Tabs from '../components/Tabs';
import { ToastProvider } from '../components/Toast';
import { useToast } from '../components/useToast';

function DialogHarness() {
  const [open, setOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open dialog
      </button>
      {open && (
        <Dialog
          label="Test dialog"
          onClose={() => setOpen(false)}
          initialFocusRef={inputRef}
          hideHeader
        >
          <input ref={inputRef} aria-label="Name" />
          <button type="button">Save</button>
        </Dialog>
      )}
    </>
  );
}

describe('Dialog', () => {
  it('focuses the requested control, traps Tab, and restores focus on Escape', async () => {
    const user = userEvent.setup();
    render(<DialogHarness />);

    await user.click(screen.getByRole('button', { name: 'Open dialog' }));
    const dialog = screen.getByRole('dialog', { name: 'Test dialog' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByLabelText('Name')).toHaveFocus();

    await user.tab({ shift: true });
    expect(screen.getByRole('button', { name: 'Save' })).toHaveFocus();
    await user.tab();
    expect(screen.getByLabelText('Name')).toHaveFocus();

    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open dialog' })).toHaveFocus();
  });
});

describe('Menu', () => {
  it('supports arrow navigation, selection, and Escape focus restoration', async () => {
    const user = userEvent.setup();
    const onFirst = vi.fn();
    const onRemove = vi.fn();

    render(
      <Menu
        label="Test actions"
        triggerLabel="Open actions"
        trigger={<span>Actions</span>}
        items={[
          { id: 'first', label: 'First action', onSelect: onFirst },
          { id: 'remove', label: 'Remove item', onSelect: onRemove, danger: true },
        ]}
      />,
    );

    const trigger = screen.getByRole('button', { name: 'Open actions' });
    await user.click(trigger);
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('menuitem', { name: 'First action' })).toHaveFocus();

    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('menuitem', { name: 'Remove item' })).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    expect(screen.getByRole('menuitem', { name: 'First action' })).toHaveFocus();
    await user.keyboard('{ArrowUp}');
    expect(screen.getByRole('menuitem', { name: 'Remove item' })).toHaveFocus();
    await user.keyboard('{Escape}');

    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();

    await user.click(trigger);
    await user.click(screen.getByRole('menuitem', { name: 'First action' }));
    expect(onFirst).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });

  it('closes when a pointer press lands outside the menu', async () => {
    const user = userEvent.setup();
    render(
      <div>
        <button type="button">Outside</button>
        <Menu
          label="Outside test"
          triggerLabel="Open menu"
          trigger={<span>Menu</span>}
          items={[{ id: 'one', label: 'One', onSelect: vi.fn() }]}
        />
      </div>,
    );

    await user.click(screen.getByRole('button', { name: 'Open menu' }));
    expect(screen.getByRole('menu')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Outside' }));
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });
});

function TabsHarness() {
  const [value, setValue] = useState('one');
  return (
    <Tabs
      label="Test sections"
      value={value}
      onChange={setValue}
      tabs={[
        { id: 'one', label: 'One' },
        { id: 'two', label: 'Two', disabled: true },
        { id: 'three', label: 'Three' },
      ]}
    />
  );
}

describe('Tabs', () => {
  it('uses roving focus and skips disabled tabs', async () => {
    const user = userEvent.setup();
    render(<TabsHarness />);

    const one = screen.getByRole('tab', { name: 'One' });
    const three = screen.getByRole('tab', { name: 'Three' });
    expect(one).toHaveAttribute('aria-selected', 'true');
    expect(one).toHaveAttribute('tabindex', '0');
    expect(three).toHaveAttribute('tabindex', '-1');

    one.focus();
    await user.keyboard('{ArrowRight}');
    expect(three).toHaveFocus();
    expect(three).toHaveAttribute('aria-selected', 'true');
    expect(three).toHaveAttribute('tabindex', '0');

    await user.keyboard('{Home}');
    expect(one).toHaveFocus();
    expect(one).toHaveAttribute('aria-selected', 'true');
  });
});

function ToastHarness() {
  const { pushToast } = useToast();
  return (
    <div>
      <button
        type="button"
        onClick={() => pushToast({ title: 'Saved', description: 'Change stored.' })}
      >
        Notify success
      </button>
      <button
        type="button"
        onClick={() => pushToast({ title: 'Failed', tone: 'error' })}
      >
        Notify error
      </button>
    </div>
  );
}

describe('Toast', () => {
  it('announces success and error toasts and dismisses them', async () => {
    const user = userEvent.setup();
    render(
      <ToastProvider>
        <ToastHarness />
      </ToastProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Notify success' }));
    expect(screen.getByRole('status')).toHaveTextContent('Saved');
    await user.click(screen.getByRole('button', { name: 'Dismiss notification: Saved' }));
    expect(screen.queryByText('Saved')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Notify error' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Failed');
  });

  it('is a safe no-op without a provider', async () => {
    const user = userEvent.setup();
    render(<ToastHarness />);

    await user.click(screen.getByRole('button', { name: 'Notify success' }));
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
