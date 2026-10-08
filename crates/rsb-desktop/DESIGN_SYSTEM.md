# RS Shield Design System v1.0

**Status**: Active | **Version**: 1.0.0 | **Last Updated**: 2026-07-26

---

## 🎯 Filosofia

- **Enterprise First**: Parecer com Docker Desktop, Warp, GitHub Desktop
- **Consistency**: Uma fonte de verdade para cada decisão visual
- **Accessibility**: WCAG AA minimum
- **Performance**: Sem sacrificar velocidade
- **Dark Mode**: Suportado nativamente

---

## 📊 Design Tokens

### 1. TIPOGRAFIA

#### Escala Hierárquica (em rem)
```
Display Large   : 2.25rem (36px) - h1 extra grande
Display        : 2rem    (32px) - main h1
Headline Large : 1.75rem (28px) - h2
Headline       : 1.5rem  (24px) - h3
Title Large    : 1.25rem (20px) - h4
Title          : 1.125rem (18px) - h5 (section-title)
Body Large     : 1rem    (16px) - main text
Body           : 0.9375rem (15px) - default
Label Large    : 0.875rem (14px) - labels
Label          : 0.8125rem (13px) - secondary labels
Caption        : 0.75rem (12px) - helper text, hints
```

#### Font Stack
```
Sans-serif: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Roboto, sans-serif
Mono:       'Menlo', 'Monaco', 'Courier New', monospace
```

#### Font Weights
```
Light   : 300
Regular : 400
Medium  : 500
Semibold: 600
Bold    : 700
```

#### Line Heights
```
Tight   : 1.2
Normal  : 1.5
Relaxed : 1.75
```

---

### 2. ESPAÇAMENTO (8px Base Scale)

```
0   : 0
1   : 4px
2   : 8px
3   : 12px
4   : 16px
5   : 20px
6   : 24px
7   : 28px
8   : 32px
9   : 36px
10  : 40px
12  : 48px
14  : 56px
16  : 64px
```

**Aplicação**:
- Padding interno de componentes: 2, 3, 4
- Margin entre elementos: 3, 4, 5
- Gaps em flexbox: 2, 3, 4
- Seção vertical spacing: 6, 8
- Page margins: 4, 6

---

### 3. CORES (TAILWIND EXTENDED)

#### Primária - Indigo
```
50  : #eef2ff
100 : #e0e7ff
200 : #c7d2fe
300 : #a5b4fc
400 : #818cf8
500 : #6366f1  ← Primary Dark Mode
600 : #4f46e5  ← Primary Light Mode
700 : #4338ca
800 : #3730a3
900 : #312e81
```

#### Sucesso - Emerald
```
50  : #f0fdf4
100 : #dcfce7
200 : #bbf7d0
300 : #86efac
400 : #4ade80
500 : #22c55e  ← Dark mode
600 : #16a34a  ← Light mode
700 : #15803d
800 : #166534
900 : #134e4a
```

#### Aviso - Amber
```
50  : #fffbeb
100 : #fef3c7
200 : #fde68a
300 : #fcd34d
400 : #fbbf24
500 : #f59e0b  ← Both modes
600 : #d97706
700 : #b45309
800 : #92400e
900 : #78350f
```

#### Perigo - Red
```
50  : #fef2f2
100 : #fee2e2
200 : #fecaca
300 : #fca5a5
400 : #f87171
500 : #ef4444  ← Dark mode
600 : #dc2626  ← Light mode
700 : #b91c1c
800 : #991b1b
900 : #7f1d1d
```

#### Neutro - Slate (Light Mode)
```
50  : #f8fafc
100 : #f1f5f9
200 : #e2e8f0
300 : #cbd5e1
400 : #94a3b8
500 : #64748b  ← Text Muted
600 : #475569
700 : #334155  ← Text Secondary
800 : #1e293b  ← Text Main
900 : #0f172a
```

#### Neutro - Slate (Dark Mode)
```
50  : #f8fafc
100 : #f1f5f9
200 : #e2e8f0
300 : #cbd5e1
400 : #94a3b8
500 : #64748b
600 : #475569
700 : #334155
800 : #1e293b  ← BG Card
900 : #0f172a  ← BG App
```

#### Blue (Informação)
```
50  : #eff6ff
100 : #dbeafe
200 : #bfdbfe
300 : #93c5fd
400 : #60a5fa
500 : #3b82f6
600 : #2563eb
700 : #1d4ed8
```

---

### 4. SOMBRAS

```
None     : none
XS       : 0 1px 2px 0 rgba(0, 0, 0, 0.05)
SM       : 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1)
Base     : 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1)
MD       : 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1)
LG       : 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1)
XL       : 0 25px 50px -12px rgba(0, 0, 0, 0.25)
2XL      : 0 25px 50px -12px rgba(0, 0, 0, 0.25)

Dark Mode: Aumentar opacity 30-50%
```

---

### 5. BORDER RADIUS

```
None   : 0
XS     : 2px
SM     : 4px
Base   : 6px
MD     : 8px
LG     : 12px
XL     : 16px
2XL    : 20px
Full   : 9999px
```

**Aplicação**:
- Inputs: MD (8px)
- Buttons: MD (8px)
- Cards: LG (12px)
- Modals: LG (12px)
- Badges: Full (9999px)

---

### 6. TRANSIÇÕES & ANIMAÇÕES

#### Durations
```
Fast   : 150ms
Normal : 300ms
Slow   : 500ms
```

#### Timing Functions
```
Ease-In-Out: cubic-bezier(0.4, 0, 0.2, 1)
Ease-Out   : cubic-bezier(0, 0, 0.2, 1)
Ease-In    : cubic-bezier(0.4, 0, 1, 1)
Linear     : linear
```

#### Common Transitions
```
colors: color 300ms ease-in-out, background-color 300ms ease-in-out, border-color 300ms ease-in-out
fade: opacity 300ms ease-in-out
slide: transform 300ms ease-out
all: all 300ms ease-in-out
```

#### Keyframe Animations
```
fadeIn       : opacity 0→1 (300ms)
slideInDown  : translateY(-10px, 0) opacity 0→1 (300ms)
slideInUp    : translateY(10px, 0) opacity 0→1 (300ms)
scaleIn      : scale 0.95→1 opacity 0→1 (300ms)
spin         : rotate 0→360 (1000ms infinite)
pulse        : opacity 1→0.5→1 (2000ms infinite)
shimmer      : shimmer effect (2000ms infinite)
```

---

## 🧩 COMPONENTES

### Button

#### Variants
```
Primary   : Indigo 600 (light) / 500 (dark)
Secondary : Slate 200 (light) / 700 (dark)
Success   : Emerald 600 (light) / 500 (dark)
Warning   : Amber 600 (light) / 500 (dark)
Danger    : Red 600 (light) / 500 (dark)
Ghost     : Transparent, texto primário
```

#### Sizes
```
XS     : px-2 py-1 text-xs
SM     : px-3 py-1.5 text-sm
MD     : px-4 py-2 text-base (default)
LG     : px-6 py-3 text-lg
XL     : px-8 py-4 text-xl
```

#### States
```
Default  : Base style
Hover    : Darken by 1 shade, shadow-md
Active   : Darken by 2 shades, shadow-none
Disabled : opacity-50, cursor-not-allowed
Loading  : spinner icon, disabled state
```

#### Properties
```
Border Radius: MD (8px)
Font Weight: 600
Transition: all 150ms ease-in-out
Icon Gap: 2 (8px)
```

---

### Input

#### Variants
```
Text      : Standard text input
Email     : Numeric keyboard, email validation
Password  : Masked input
Number    : Number keyboard
Textarea  : Multi-line
Select    : Dropdown
Checkbox  : Boolean
Radio     : Single choice
Range     : Slider
```

#### States
```
Empty    : Gray border, placeholder visible
Filled   : Blue border on focus
Error    : Red border, error message
Success  : Green border, checkmark
Disabled : Gray bg, opacity-50
Loading  : Spinner right side
Readonly : Gray bg, no interaction
```

#### Properties
```
Border Radius: MD (8px)
Padding: 3 vertical (12px), 4 horizontal (16px)
Border: 1px solid
Font: Body (0.9375rem)
Focus Shadow: 0 0 0 3px rgba(79, 70, 229, 0.1)
Transition: all 150ms ease-in-out
```

---

### Card

#### Variants
```
Elevated : Shadow-md, bg-white
Outlined : 1px border, no shadow
Filled   : bg-slate-50, subtle
Flat     : Minimal, just spacing
```

#### States
```
Default  : Base style
Hover    : Raise shadow (if elevated), highlight border
Active   : Accent border
Disabled : opacity-50
```

#### Properties
```
Border Radius: LG (12px)
Padding: 6 (24px)
Shadow: MD or None depending variant
Transition: all 300ms ease-in-out
```

---

### Badge

#### Variants
```
Primary  : Indigo background + text
Success  : Emerald background + text
Warning  : Amber background + text
Danger   : Red background + text
Neutral  : Slate background + text
```

#### Sizes
```
SM : px-2 py-1 text-xs
MD : px-3 py-1.5 text-sm
LG : px-4 py-2 text-base
```

#### Properties
```
Border Radius: Full (9999px)
Font Weight: 600
Padding: Compact
```

---

### Empty State

#### Structure
```
Icon          : Large emoji or SVG (4rem)
Title         : Headline (1.5rem)
Description   : Body (0.9375rem)
Action Button : Primary or Secondary
```

#### Properties
```
Spacing: 6 vertical (24px)
Alignment: Center
Colors: Gray text + primary CTA
```

---

### Error State

#### Structure
```
Icon           : ❌ or ⚠️
Title          : Error title
Description    : Error detail
Retry/Dismiss  : Buttons
```

#### Properties
```
Border Left: 4px red
Background: Red 50 (light) / Red 900/20 (dark)
Text: Red 900 (light) / Red 300 (dark)
```

---

### Loading State

#### Variants
```
Spinner      : Animated spinner
Dots         : Animated dots (•••)
ProgressBar  : Linear progress
Pulse        : Pulsing animation
Skeleton     : Shimmer effect
```

#### Properties
```
Duration: 1000-2000ms
Color: Primary indigo
Message: Body text below
```

---

## 🎨 APLICAÇÃO PRÁTICA

### Page Layout
```rust
div { class: "flex flex-col gap-6 p-6",
    // Header
    div { class: "flex items-center justify-between gap-4",
        h1 { class: "text-display font-bold" } // 2rem
        // Actions
    }
    
    // Content
    div { class: "grid gap-4",
        // Cards
    }
}
```

### Form Layout
```rust
form { class: "space-y-4",
    // Input groups
    div { class: "flex flex-col gap-1.5",
        label { class: "text-label-large font-semibold" } // 14px
        input { class: "input-field" }
        p { class: "text-caption text-text-muted" } // 12px
    }
}
```

### Card Grid
```rust
div { class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4",
    Card { /* ... */ }
}
```

---

## ✅ CHECKLIST DE APLICAÇÃO

- [ ] Todas as fontes usam escala definida
- [ ] Todos os espaçamentos usam escala 8px
- [ ] Todas as cores usam tokens definidos
- [ ] Todos os radii usam escala definida
- [ ] Todas as sombras usam escala definida
- [ ] Todos os componentes têm estados definidos
- [ ] Transições sempre 150ms ou 300ms
- [ ] Dark mode implementado para cada elemento
- [ ] WCAG AA tested
- [ ] LoginScreen como referência

---

## 📚 Referências

- Componentes base em: `src/ui/components/`
- Estilos em: `src/ui/styles.css` + `tailwind.config.js`
- Uso em: Cada screen respeita tokens

**Última revisão**: 2026-07-26
