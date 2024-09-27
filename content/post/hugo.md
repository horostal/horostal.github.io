---
date: "2024-09-23"
title: hugo
---

将博客从hexo迁到hugo，很多配置项都不太一样，重新看起官方说明。环境安装如果有go、Node.js问题不大，主题选用了blowfish，最简单是跟着官方的[教程](https://blowfish.page/zh-cn/docs/getting-started/)走。

主目录下`content`跟发布内容相关，`assets`则是可以访问到的图片等文件存放地址，`layouts`则是各种渲染，虽然说blowfish集成了katex，但无法直接使用，找到`\themes\blowfish\layouts\shortcodes`会发现里面是简码文件，且`katex.html`里面内容为空，其他不为空的简码也无法使用，最后根据[Chlorine](https://www.yoghurtlee.com/hugo-math-rendering)解决公式渲染问题和多行无法显示问题，正如文章里那样将`themes\blowfish\layouts\partials\head.html`放到`layouts\partials\head.html`，主目录权重更高，同名文件执行主目录下，也为了备份需求，万一改坏了还能复原；修改`head.html`并加入

```html
{{/* KaTeX */}}
<link rel="preload" href="https://cdn.bootcdn.net/ajax/libs/KaTeX/0.16.8/katex.min.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
<noscript>
  <link rel="stylesheet" href="https://cdn.bootcdn.net/ajax/libs/KaTeX/0.16.8/katex.min.css">
</noscript>
<script defer src="https://cdn.bootcdn.net/ajax/libs/KaTeX/0.16.8/katex.min.js" crossorigin="anonymous"></script>
<script defer src="https://cdn.bootcdn.net/ajax/libs/KaTeX/0.16.8/contrib/auto-render.min.js" crossorigin="anonymous"
    onload="renderMathInElement(document.body, {
          delimiters: [
            { left: '$$', right: '$$', display: true },
            { left: '$', right: '$', display: false },
            { left: '\$', right: '\$', display: false }
          ]
        });"></script>
```

`blowfish`本身就安装有`goldmark`插件，修改`config\_default\markup.toml`，在里面加入

```toml
[goldmark.extensions.passthrough]
      enable = true
      delimiters.block = [
        ["\\[", "\\]"],
        ["$$", "$$"]
      ]
      delimiters.inline = [
        ["\\(", "\\)"],
        ["$", "$"]
      ]
```

