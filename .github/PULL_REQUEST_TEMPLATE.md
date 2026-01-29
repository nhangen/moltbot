# Pull Request: [Title]

<!--
  Guidelines for a great PR:
  - Use a clear, descriptive title following conventional commits format
  - Fill out all relevant sections below
  - Delete sections that don't apply (but keep the core sections)
  - Reference related issues and PRs
  - Add screenshots/videos for UI changes
  - Ensure all tests pass and code is properly formatted
-->

## 📋 Summary

<!--
  Provide a clear, concise summary (2-4 sentences) of what this PR does.
  Focus on WHAT changed and WHY, not HOW (code explains the how).
-->

## 🎯 Related Issues

<!--
  Link to related issues, PRs, or documentation:
  - Closes #123
  - Related to #456
  - Depends on #789
  - Reference: [Document Name](/path/to/doc.md)
-->

Closes #

## 🚀 What's New

<!--
  Detail the changes made in this PR. Organize by feature/component.
  Use subheadings (###) for major sections.
  Include code snippets for complex changes.
-->

### Core Changes

#### 1. [Feature/Component Name]

**Purpose**: [Why this change was made]

**Implementation**:

- Change 1
- Change 2
- Change 3

**Key Code** (if applicable):

```javascript
// Show important code snippets with file paths
// /path/to/file.js:123-145
```

## 📊 Type of Change

<!-- Check all that apply -->

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to change)
- [ ] 📝 Documentation update
- [ ] 🔧 Configuration change
- [ ] ♻️ Code refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] 🎨 UI/UX change
- [ ] 🧪 Test coverage improvement
- [ ] 🔒 Security fix

## 🧪 Testing

<!--
  Describe testing performed to validate changes.
  Include both automated tests and manual testing.
-->

### Automated Tests

- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All existing tests pass

**Test Coverage**:

- [ ] New code has test coverage
- [ ] Edge cases covered
- [ ] Error handling tested

**Test Results**:

```bash
# Include test output or summary
✓ 42 tests passing
✓ 0 tests failing
```

### Manual Testing

<!-- Describe manual testing steps performed -->

**Testing Checklist**:

- [ ] Tested in development environment
- [ ] Tested in staging environment (if applicable)
- [ ] Tested with real data/production-like scenarios
- [ ] Tested error scenarios
- [ ] Verified no console errors/warnings
- [ ] Checked browser console for issues (frontend changes)

**Environments Tested**:

- [ ] Development
- [ ] Staging
- [ ] Production (if safe to test)

## 📸 Screenshots/Videos

<!--
  Include screenshots or videos for UI changes.
  Use before/after comparisons for visual changes.
  Delete this section if not applicable.
-->

### Before

<!-- Screenshot/video of previous behavior -->

### After

<!-- Screenshot/video of new behavior -->

## 🚀 Deployment Strategy

<!--
  Describe how this should be deployed.
  Include rollout plan for risky changes.
-->

### Deployment Steps

1. Step 1
2. Step 2
3. Step 3

### Configuration Changes

<!-- List any environment variables, feature flags, or config changes needed -->

- [ ] Environment variables added/updated: `VARIABLE_NAME=value`
- [ ] Feature flags required: `FEATURE_FLAG=true`
- [ ] Database migrations needed
- [ ] External service configuration required

### Phased Rollout (if applicable)

- [ ] **Phase 1**: Deploy to staging for validation (recommended duration: X days)
- [ ] **Phase 2**: Deploy to production with feature flag disabled
- [ ] **Phase 3**: Enable feature flag for production traffic
- [ ] **Phase 4**: Monitor metrics and remove feature flag

## 🔙 Rollback Plan

<!--
  Describe how to quickly rollback if issues occur.
  Critical for production deployments.
-->

**Quick Rollback**:

- Disable feature flag: `FEATURE_FLAG=false` and restart service (< 1 minute)
- OR: Revert to previous deployment revision
- OR: Git revert commit hash

**Cleanup Required** (if rollback is performed):

- [ ] Database changes to revert
- [ ] Cache to clear
- [ ] External services to notify

## 💰 Cost Impact

<!--
  Estimate cost impact for cloud services, APIs, storage, etc.
  Delete if not applicable.
-->

**Expected Cost Changes**:

- Cloud Run: +/- $X/month
- Storage: +/- $X/month
- API calls: +/- $X/month
- **Total Estimated Impact**: +/- $X/month

**Cost Optimization Notes**:

- [Explain any cost optimizations included]

## ⚡ Performance Impact

<!--
  Describe performance impact (positive or negative).
  Include benchmarks for significant changes.
-->

**Expected Performance Changes**:

- Response time: +/- Xms
- Memory usage: +/- XMB
- Database queries: +/- X queries
- API calls: +/- X calls

**Benchmarks** (if applicable):

```text
Before: Xms average response time
After:  Xms average response time
```

## 🔍 Code Quality

<!--
  Pre-commit hooks should catch most issues automatically.
  Confirm code quality checks passed.
-->

- [x] ESLint passed (auto-checked by pre-commit hooks)
- [x] Prettier formatting applied (auto-checked by pre-commit hooks)
- [x] Markdownlint passed for docs (auto-checked by pre-commit hooks)
- [x] Commit messages follow conventional commits
- [ ] Code reviewed by AI agent or peer
- [ ] No console.log statements in production code
- [ ] No commented-out code left behind
- [ ] Error handling implemented for edge cases
- [ ] Security considerations reviewed (XSS, SQL injection, auth, etc.)

## 📚 Documentation

<!--
  Ensure documentation is updated for changes.
  Delete sections that don't apply.
-->

- [ ] README.md updated (if user-facing changes)
- [ ] CONTRIBUTING.md updated (if dev workflow changes)
- [ ] API documentation updated (if API changes)
- [ ] Inline code comments added for complex logic
- [ ] Architecture documentation updated (if structural changes)
- [ ] CLAUDE.md updated (for AI context in future sessions)

## 🔐 Security Considerations

<!--
  Address security implications of changes.
  Required for security-sensitive changes.
-->

- [ ] No sensitive data logged or exposed
- [ ] Authentication/authorization implemented correctly
- [ ] Input validation added for user input
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (sanitized output)
- [ ] CSRF protection (if applicable)
- [ ] Secrets stored securely (not in code/logs)
- [ ] Rate limiting considered (if applicable)

## 📋 Pre-Merge Checklist

<!--
  Final checklist before merging.
  All items should be checked.
-->

- [ ] All tests pass locally
- [ ] All pre-commit hooks pass
- [ ] Code has been self-reviewed
- [ ] Changes generate no new warnings
- [ ] Dependent changes have been merged
- [ ] Documentation has been updated
- [ ] Reviewer(s) have approved the PR
- [ ] Branch is up to date with base branch
- [ ] Commit messages are clean and descriptive
- [ ] Ready for production deployment

## 🔗 Additional Context

<!--
  Add any additional context, screenshots, benchmarks, or notes.
  Links to external resources, design docs, API references, etc.
-->

## 🚦 Status

<!-- Update as PR progresses -->

- [ ] 🔴 Draft - Work in progress
- [ ] 🟡 Ready for Review - Code complete, needs review
- [ ] 🟢 Approved - Ready to merge
- [ ] 🔵 Merged - Deployed to staging
- [ ] ✅ Complete - Deployed to production

---

<!--
  For Reviewers:
  - Check code quality and adherence to project standards
  - Verify tests cover new functionality
  - Confirm documentation is updated
  - Test changes locally if possible
  - Ensure security considerations are addressed
  - Validate deployment plan is safe
-->
