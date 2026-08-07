"""
Conversation state constants shared across all admin handlers.
"""

(
    STATE_MAIN_MENU,
    STATE_TOKEN_PICK,   # guideline flow: admin picks which employee to guide
    STATE_OS_PICK,      # guideline flow: admin picks OS
    STATE_CSR_PICK,     # submit CSR flow: admin picks which employee's CSR to submit
    STATE_AWAIT_CSR,    # submit CSR flow: waiting for .csr file upload
    STATE_CSR_CONFIRM,  # submit CSR flow: filename mismatch — confirm or re-upload
) = range(6)

