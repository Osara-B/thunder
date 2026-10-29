// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

import {
  Alert,
  Box,
  Checkbox,
  FormControl,
  FormControlLabel,
  FormHelperText,
  FormLabel,
  MenuItem,
  Select,
  Stack,
  Typography,
} from '@wso2/oxygen-ui';
import {useEffect, type JSX} from 'react';
import {useTranslation} from 'react-i18next';
import {DELIMITER_OPTIONS} from '../../config/resource-server-delimiters';
import {DEFAULT_PERMISSION_DELIMITER} from '../../constants/permission-constants';
import type {PermissionDelimiter} from '../../models/permissions';
import {isValidPermissionDelimiter} from '../../utils/isValidPermissionDelimiter';

interface ConfigureSeparatorProps {
  delimiter: PermissionDelimiter;
  onDelimiterChange: (delimiter: PermissionDelimiter) => void;
  hierarchicalPermissions: boolean;
  onHierarchicalPermissionsChange: (enabled: boolean) => void;
  onReadyChange?: (isReady: boolean) => void;
}

export default function ConfigureSeparator({
  delimiter,
  onDelimiterChange,
  hierarchicalPermissions,
  onHierarchicalPermissionsChange,
  onReadyChange = undefined,
}: ConfigureSeparatorProps): JSX.Element {
  const {t} = useTranslation();

  const isDelimiterValid = isValidPermissionDelimiter(delimiter);

  useEffect((): void => {
    if (onReadyChange) {
      onReadyChange(isDelimiterValid);
    }
  }, [isDelimiterValid, onReadyChange]);

  const permissionPreview = `<resource>${delimiter}<action>`;

  return (
    <Stack direction="column" spacing={4}>
      <Stack direction="column" spacing={0.5}>
        <Typography variant="h1" gutterBottom>
          {t('resourceServers:create.separator.title', 'Choose your permission delimiter')}
        </Typography>
        <Typography variant="body1" color="text.secondary">
          {t(
            'resourceServers:create.separator.subtitle',
            'The delimiter character joins parts of a permission string. This cannot be changed after creation.',
          )}
        </Typography>
      </Stack>

      <FormControl fullWidth required error={!isDelimiterValid}>
        <FormLabel htmlFor="resource-server-separator-select">
          {t('resourceServers:create.separator.label', 'Permission delimiter')}
        </FormLabel>
        <Select
          id="resource-server-separator-select"
          value={isValidPermissionDelimiter(delimiter) ? delimiter : DEFAULT_PERMISSION_DELIMITER}
          onChange={(e) => {
            const val = e.target.value;
            if (isValidPermissionDelimiter(val)) {
              onDelimiterChange(val);
            }
          }}
        >
          {DELIMITER_OPTIONS.map((opt) => (
            <MenuItem key={opt.value} value={opt.value}>
              {t(opt.labelKey, opt.labelFallback)}
            </MenuItem>
          ))}
        </Select>
        {!isDelimiterValid ? (
          <FormHelperText>
            {t('resourceServers:create.separator.invalid', 'Select a valid delimiter: . _ : - /')}
          </FormHelperText>
        ) : (
          <FormHelperText>
            {t(
              'resourceServers:create.separator.hint',
              'Choose the character that separates parts of a permission string.',
            )}
          </FormHelperText>
        )}
      </FormControl>

      <Box
        sx={{
          p: 1.5,
          bgcolor: 'action.hover',
          borderRadius: 1,
          border: '1px solid',
          borderColor: 'divider',
        }}
      >
        <Typography variant="caption" color="text.secondary" display="block" sx={{mb: 0.5}}>
          {t('resourceServers:create.separator.previewLabel', 'Example permission')}
        </Typography>
        <Typography variant="body2" sx={{fontFamily: 'monospace'}}>
          {permissionPreview}
        </Typography>
      </Box>

      <FormControl>
        <FormControlLabel
          control={
            <Checkbox
              id="resource-server-hierarchical-permissions"
              checked={hierarchicalPermissions}
              onChange={(e) => onHierarchicalPermissionsChange(e.target.checked)}
            />
          }
          label={t('resourceServers:create.separator.hierarchical.label', 'Permissions are hierarchical')}
        />
        <FormHelperText sx={{ml: 0}}>
          {t(
            'resourceServers:create.separator.hierarchical.hint',
            'Granting a resource also grants the permissions beneath it. Leave this off if your API treats each permission as a separate value.',
          )}
        </FormHelperText>
        {hierarchicalPermissions && (
          <Alert severity="info" sx={{mt: 1.5}}>
            {t(
              'resourceServers:create.separator.hierarchical.notice',
              'A grant covers permissions added beneath it later, so a resource added under one a role already grants is granted too.',
            )}
          </Alert>
        )}
      </FormControl>
    </Stack>
  );
}
