// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import userEvent from '@testing-library/user-event';
import {render, screen} from '@thunderid/test-utils';
import {describe, expect, it, vi} from 'vitest';
import ConfigureSeparator from '../ConfigureSeparator';

describe('ConfigureSeparator', () => {
  it('renders the separator select element', () => {
    render(
      <ConfigureSeparator
        delimiter=":"
        onDelimiterChange={vi.fn()}
        hierarchicalPermissions={false}
        onHierarchicalPermissionsChange={vi.fn()}
      />,
    );

    expect(screen.getByRole('combobox')).toBeInTheDocument();
  });

  it('renders the permission preview without a resource server prefix', () => {
    render(
      <ConfigureSeparator
        delimiter=":"
        onDelimiterChange={vi.fn()}
        hierarchicalPermissions={false}
        onHierarchicalPermissionsChange={vi.fn()}
      />,
    );

    expect(screen.getByText('<resource>:<action>')).toBeInTheDocument();
  });

  it('renders preview using dot separator', () => {
    render(
      <ConfigureSeparator
        delimiter="."
        onDelimiterChange={vi.fn()}
        hierarchicalPermissions={false}
        onHierarchicalPermissionsChange={vi.fn()}
      />,
    );

    expect(screen.getByText('<resource>.<action>')).toBeInTheDocument();
  });

  it('calls onReadyChange with true when delimiter is valid', () => {
    const onReadyChange = vi.fn();
    render(
      <ConfigureSeparator
        delimiter=":"
        onDelimiterChange={vi.fn()}
        hierarchicalPermissions={false}
        onHierarchicalPermissionsChange={vi.fn()}
        onReadyChange={onReadyChange}
      />,
    );

    expect(onReadyChange).toHaveBeenCalledWith(true);
  });

  it('leaves hierarchical permissions off by default', () => {
    render(
      <ConfigureSeparator
        delimiter=":"
        onDelimiterChange={vi.fn()}
        hierarchicalPermissions={false}
        onHierarchicalPermissionsChange={vi.fn()}
      />,
    );

    expect(screen.getByRole('checkbox', {name: /Permissions are hierarchical/i})).not.toBeChecked();
  });

  it('reports the choice when the box is ticked', async () => {
    const user = userEvent.setup();
    const onHierarchicalPermissionsChange = vi.fn();
    render(
      <ConfigureSeparator
        delimiter=":"
        onDelimiterChange={vi.fn()}
        hierarchicalPermissions={false}
        onHierarchicalPermissionsChange={onHierarchicalPermissionsChange}
      />,
    );

    await user.click(screen.getByRole('checkbox', {name: /Permissions are hierarchical/i}));

    expect(onHierarchicalPermissionsChange).toHaveBeenCalledWith(true);
  });

  // The delimiter stops being only a formatting choice once permissions nest, so the consequence is
  // stated where the choice is made rather than left to documentation.
  it('warns about delimiter choice and later additions only while enabled', () => {
    const {rerender} = render(
      <ConfigureSeparator
        delimiter=":"
        onDelimiterChange={vi.fn()}
        hierarchicalPermissions={false}
        onHierarchicalPermissionsChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/added beneath it later/i)).not.toBeInTheDocument();

    rerender(
      <ConfigureSeparator
        delimiter=":"
        onDelimiterChange={vi.fn()}
        hierarchicalPermissions
        onHierarchicalPermissionsChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/added beneath it later/i)).toBeInTheDocument();
  });
});
