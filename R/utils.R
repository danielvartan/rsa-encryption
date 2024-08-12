test_public_key <- function(public_key) {
  test <-
    public_key |>
    openssl::read_pubkey() |>
    try(silent = TRUE)

  if (!inherits(test, "try-error")) {
    TRUE
  } else {
    FALSE
  }
}

test_private_key <- function(private_key, password = NULL) {
  checkmate::assert_string(password, null.ok = TRUE)

  test <-
    private_key |>
    openssl::read_key(password = password) |>
    try(silent = TRUE)

  if (!inherits(test, "try-error")) {
    TRUE
  } else {
    FALSE
  }
}
