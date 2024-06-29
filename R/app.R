library(bslib)
library(shiny)
library(shinyjs)

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

ui <- bslib::page_fillable(
  shinyjs::useShinyjs(),
  tags$style(".btn: {width: 50%;}"),

  shiny::div(
    shiny::tags$p(paste0(
      "This Shiny app allows you to encrypt and decrypt files. ",
      "Please note that only OpenSSL-generated keys are supported."
    )),
    class = "container d-flex align-items-center justify-content-center"
  ),

  bslib::layout_columns(
    bslib::card(
      bslib::card_header("Encrypt file"),
      shiny::fileInput("upload_unlocked_file", "Upload an unlocked file"),

      shiny::fileInput("upload_public_key", "Upload an RSA public key"),
      shiny::textOutput("public_key_feedback"),

      shiny::downloadButton(
        outputId = "download_locked",
        label  = "Download locked file",
        class = "shiny-input-container"
      )
    ),
    bslib::card(
      bslib::card_header("Decrypt file"),
      shiny::fileInput("upload_locked_file", "Upload a locked file"),
      shiny::fileInput("upload_private_key", "Upload an RSA private key"),

      shiny::passwordInput(
        "password",
        "Input the private key password (if there is one)"
      ),
      shiny::textOutput("private_key_feedback"),

      shiny::downloadButton(
        outputId = "download_unlocked",
        label  = "Download unlocked file",
        class = "shiny-input-container"
      )
    ),
    col_widths = c(-2, 4, -0.5, 4, -2),
    fill = TRUE,
    fillable = TRUE
  )
)

server <- function(input, output) {
  output$public_key_feedback <- shiny::reactive({
    if (!is.null(input$upload_public_key) &&
        !test_public_key(input$upload_public_key$datapath)) { #nolint
      shiny::validate("This public key is not valid.")
    }
  })

  output$download_locked <- shiny::downloadHandler(
    filename = function() {
      paste0(input$upload_unlocked_file$name, ".lockr")
    },
    content = function(file) {
      con <- file(file, "wb")

      openssl::encrypt_envelope(
        data = input$upload_unlocked_file$datapath,
        pubkey = input$upload_public_key$datapath
      ) |>
        saveRDS(file = con)

      close(con)
    }
  )

  shiny::observe({
    if (is.null(input$upload_unlocked_file) ||
        is.null(input$upload_public_key) || #nolint
        !test_public_key(input$upload_public_key$datapath)) { #nolint
      shinyjs::disable("download_locked")
    } else {
      shinyjs::enable("download_locked")
    }
  })

  output$private_key_feedback <- shiny::reactive({
    if (!is.null(input$upload_private_key) &&
        !test_private_key(input$upload_private_key$datapath, input$password)) {
      shiny::validate(paste0(
        "This private key is not valid, ",
        "or the password provided doesn't work with the key."
      ))
    }
  })

  output$download_unlocked <- shiny::downloadHandler(
    filename = function() {
      name <- input$upload_locked_file$name
      if (grepl("\\.lockr$", name)) name <- gsub("\\.lockr$", "", name)

      name
    },
    content = function(file) {
      data <- readRDS(input$upload_locked_file$datapath)
      con <- file(file, "wb")

      openssl::decrypt_envelope(
        data = data$data,
        iv = data$iv,
        session = data$session,
        key = input$upload_private_key$datapath,
        password = ifelse(input$password == "", NULL, input$password)
      ) |>
        writeBin(con = file)

      close(con)
    }
  )

  shiny::observe({
    if (is.null(input$upload_locked_file) ||
        is.null(input$upload_private_key) || #nolint
        !test_private_key(input$upload_private_key$datapath, input$password)) {
      shinyjs::disable("download_unlocked")
    } else {
      shinyjs::enable("download_unlocked")
    }
  })
}

shiny::shinyApp(ui = ui, server = server)
