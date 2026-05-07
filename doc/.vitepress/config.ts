import { defineConfig } from 'vitepress'

const enSidebar = [
  {
    text: '🚀 Quick Start',
    items: [
      { text: 'Project Introduction', link: '/guide/project-intro' },
      { text: 'Home', link: '/' },
      { text: 'Quick Start Guide', link: '/guide/quick-start' },
    ]
  },
  {
    text: '📖 Basics',
    items: [
      { text: 'StpUtil API Reference', link: '/guide/stp-util' },
      { text: 'Permission Matching', link: '/guide/permission-matching' },
      { text: 'Event Listeners', link: '/guide/event-listener' },
      { text: 'Event Listener Quick Start', link: '/guide/event-listener-quickstart' },
      { text: 'Path Auth Guide', link: '/guide/path-auth' },
      { text: 'Token Styles', link: '/guide/token-styles' },
    ]
  },
  {
    text: '🎯 Advanced',
    items: [
      { text: 'JWT Guide', link: '/guide/jwt' },
      { text: 'OAuth2 Guide', link: '/guide/oauth2' },
      { text: 'Security Features', link: '/guide/security-features' },
      { text: 'WebSocket Authentication', link: '/guide/websocket-auth' },
      { text: 'Online User Management', link: '/guide/online-user-management' },
      { text: 'Distributed Session', link: '/guide/distributed-session' },
      { text: 'SSO Single Sign-On', link: '/guide/sso' },
      { text: 'Framework Integration', link: '/guide/framework-integration' },
    ]
  },
  {
    text: 'Reference',
    items: [
      { text: 'Error Reference', link: '/reference/error-reference' },
    ]
  },
]

const zhSidebar = [
  {
    text: '🚀 快速入门',
    items: [
      { text: '项目介绍', link: '/zh/guide/project-intro' },
      { text: '首页', link: '/zh/' },
      { text: '快速入门指南', link: '/zh/guide/quick-start' },
    ]
  },
  {
    text: '📖 基础',
    items: [
      { text: 'StpUtil API 参考', link: '/zh/guide/stp-util' },
      { text: '权限匹配规则', link: '/zh/guide/permission-matching' },
      { text: '事件监听器', link: '/zh/guide/event-listener' },
      { text: '事件监听器快速入门', link: '/zh/guide/event-listener-quickstart' },
      { text: '路径鉴权指南', link: '/zh/guide/path-auth' },
      { text: 'Token 风格', link: '/zh/guide/token-styles' },
    ]
  },
  {
    text: '🎯 进阶',
    items: [
      { text: 'JWT 指南', link: '/zh/guide/jwt' },
      { text: 'OAuth2 指南', link: '/zh/guide/oauth2' },
      { text: '安全特性', link: '/zh/guide/security-features' },
      { text: 'WebSocket 认证', link: '/zh/guide/websocket-auth' },
      { text: '在线用户管理', link: '/zh/guide/online-user-management' },
      { text: '分布式 Session', link: '/zh/guide/distributed-session' },
      { text: 'SSO 单点登录', link: '/zh/guide/sso' },
      { text: '框架集成', link: '/zh/guide/framework-integration' },
    ]
  },
  {
    text: '参考',
    items: [
      { text: '错误参考', link: '/zh/reference/error-reference' },
    ]
  },
]

export default defineConfig({
  title: 'sa-token-rust',
  description: 'Lightweight authentication and authorization framework for Rust',
  base: '/sa-token-rust/',

  head: [
    ['link', { rel: 'icon', href: '/favicon.ico' }],
  ],

  locales: {
    root: {
      label: 'English',
      lang: 'en-US',
      themeConfig: {
        nav: [
          { text: 'Home', link: '/' },
          { text: 'Quick Start', link: '/guide/quick-start' },
          { text: 'Guide', link: '/guide/stp-util' },
          { text: 'GitHub', link: 'https://github.com/sa-tokens/sa-token-rust' },
        ],
        sidebar: enSidebar,
        editLink: {
          pattern: 'https://github.com/sa-tokens/sa-token-rust/edit/main/doc/:path',
        },
        footer: {
          message: 'Released under the Apache-2.0 / MIT License.',
        },
      },
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      themeConfig: {
        nav: [
          { text: '首页', link: '/zh/' },
          { text: '快速入门', link: '/zh/guide/quick-start' },
          { text: '指南', link: '/zh/guide/stp-util' },
          { text: 'GitHub', link: 'https://github.com/sa-tokens/sa-token-rust' },
        ],
        sidebar: zhSidebar,
        editLink: {
          pattern: 'https://github.com/sa-tokens/sa-token-rust/edit/main/doc/:path',
        },
        footer: {
          message: '基于 Apache-2.0 / MIT 协议发布。',
        },
      },
    },
  },

  themeConfig: {
    logo: false,
    search: {
      provider: 'local',
      options: {
        locales: {
          root: {
            translations: {
              button: { buttonText: 'Search' },
            },
          },
          zh: {
            translations: {
              button: { buttonText: '搜索' },
            },
          },
        },
      },
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/sa-tokens/sa-token-rust' },
    ],
  },

  markdown: {
    lineNumbers: true,
  },

  vite: {
    assetsInclude: ['**/*.JPG', '**/*.jpg', '**/*.jpeg', '**/*.png'],
  },
})
