import type { ComponentType, SVGProps } from 'react';
import {
  ActivityIcon,
  FileIcon,
  KeyIcon,
  OverviewIcon,
  ShareIcon,
  UsersIcon,
} from '../components/Icons';

export type NavIcon = ComponentType<SVGProps<SVGSVGElement>>;

export interface NavItem {
  to: string;
  label: string;
  description: string;
  icon: NavIcon;
  adminOnly?: boolean;
  end?: boolean;
  keywords?: string[];
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Workspace',
    items: [
      {
        to: '/',
        label: 'Overview',
        description: 'Session, role, and workspace shortcuts',
        icon: OverviewIcon,
        end: true,
        keywords: ['home', 'dashboard', 'account'],
      },
      {
        to: '/documents',
        label: 'My documents',
        description: 'Upload, search, and manage files',
        icon: FileIcon,
        keywords: ['files', 'upload', 'library'],
      },
    ],
  },
  {
    label: 'Sharing',
    items: [
      {
        to: '/shared',
        label: 'Shared with me',
        description: 'Files another owner has shared',
        icon: ShareIcon,
        keywords: ['files', 'grants', 'access'],
      },
      {
        to: '/access',
        label: 'Access & sharing',
        description: 'Review grants on documents you own',
        icon: KeyIcon,
        keywords: ['permissions', 'revoke', 'sharing'],
      },
    ],
  },
  {
    label: 'Administration',
    items: [
      {
        to: '/admin/users',
        label: 'User management',
        description: 'Roles, activation, and sessions',
        icon: UsersIcon,
        adminOnly: true,
        keywords: ['admin', 'users', 'accounts', 'roles', 'sessions'],
      },
      {
        to: '/admin/audit',
        label: 'Audit',
        description: 'Audit events, document activity, and verification',
        icon: ActivityIcon,
        adminOnly: true,
        keywords: ['audit', 'transactions', 'events', 'documents', 'verification', 'admin', 'security'],
      },
    ],
  },
];

export function navigationGroupsForRole(role: string): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.adminOnly || role === 'admin'),
  })).filter((group) => group.items.length > 0);
}

export function navigationItemsForRole(role: string): NavItem[] {
  return navigationGroupsForRole(role).flatMap((group) => group.items);
}

export function canManageDocuments(role: string): boolean {
  return role === 'owner' || role === 'admin';
}

export function pageTitleFor(pathname: string): string {
  if (pathname.startsWith('/documents/')) {
    return 'Document details';
  }
  if (pathname.startsWith('/documents')) {
    return 'My documents';
  }
  if (pathname.startsWith('/shared')) {
    return 'Shared with me';
  }
  if (pathname.startsWith('/access')) {
    return 'Access & sharing';
  }
  if (pathname.startsWith('/admin/audit') || pathname.startsWith('/activity')) {
    return 'Audit';
  }
  if (pathname.startsWith('/admin/users')) {
    return 'User management';
  }
  if (pathname.startsWith('/settings')) {
    return 'Settings';
  }
  return 'Overview';
}
