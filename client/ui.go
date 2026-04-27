package main

import (
	"flag"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

var (
	fyneApp    fyne.App
	mainWindow fyne.Window
)

func main() {
	relayURL := flag.String("relay", "ws://localhost:9000/ws", "relay WebSocket URL")
	debug := flag.Bool("debug", false, "enable debug mode")
	flag.Parse()

	fyneApp = app.New()
	mainWindow = fyneApp.NewWindow("SecureRelay Messenger")
	mainWindow.Resize(fyne.NewSize(700, 500))

	showLoginScreen(*relayURL, *debug)
	mainWindow.ShowAndRun()
}

// safeCall runs fn and converts any panic into a returned error.
func safeCall(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	fn()
	return nil
}

func showLoginScreen(defaultRelay string, defaultDebug bool) {
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("e.g. alice")

	relayEntry := widget.NewEntry()
	relayEntry.SetText(defaultRelay)

	debugCheck := widget.NewCheck("Debug mode", nil)
	debugCheck.SetChecked(defaultDebug)

	statusLabel := widget.NewLabel("")

	connectBtn := widget.NewButton("Connect", func() {
		username := strings.TrimSpace(usernameEntry.Text)
		relay := strings.TrimSpace(relayEntry.Text)
		if username == "" {
			dialog.ShowError(fmt.Errorf("username cannot be empty"), mainWindow)
			return
		}
		statusLabel.SetText("Connecting...")
		go func() {
			if err := initClientWithParams(username, relay, debugCheck.Checked); err != nil {
				fyne.Do(func() {
					statusLabel.SetText("")
					dialog.ShowError(err, mainWindow)
				})
				return
			}
			if err := safeCall(func() { RegisterWithRelay(&Client) }); err != nil {
				fyne.Do(func() {
					statusLabel.SetText("")
					dialog.ShowError(fmt.Errorf("registration failed: %v", err), mainWindow)
				})
				return
			}
			fyne.Do(showPeerSelectScreen)
		}()
	})

	mainWindow.SetContent(container.NewCenter(
		container.NewVBox(
			widget.NewRichTextFromMarkdown("## SecureRelay Messenger"),
			widget.NewSeparator(),
			widget.NewForm(
				widget.NewFormItem("Username", usernameEntry),
				widget.NewFormItem("Relay URL", relayEntry),
			),
			debugCheck,
			connectBtn,
			statusLabel,
		),
	))
}

func showPeerSelectScreen() {
	users := binding.NewStringList()
	statusLabel := widget.NewLabel("")
	var selectedPeer string

	connectBtn := widget.NewButton("Connect to Peer", func() {
		if selectedPeer == "" {
			return
		}
		Client.peerId = selectedPeer
		statusLabel.SetText("Setting up session...")
		go func() {
			if err := safeCall(func() { CreateClientSession(&Client) }); err != nil {
				fyne.Do(func() {
					statusLabel.SetText("")
					dialog.ShowError(fmt.Errorf("session setup failed: %v", err), mainWindow)
				})
				return
			}
			fyne.Do(showChatScreen)
		}()
	})
	connectBtn.Disable()

	userList := widget.NewListWithData(users,
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(item binding.DataItem, obj fyne.CanvasObject) {
			s, _ := item.(binding.String).Get()
			obj.(*widget.Label).SetText(s)
		},
	)
	userList.OnSelected = func(id widget.ListItemID) {
		u, _ := users.GetValue(id)
		selectedPeer = u
		connectBtn.Enable()
	}
	userList.OnUnselected = func(_ widget.ListItemID) {
		selectedPeer = ""
		connectBtn.Disable()
	}

	doRefresh := func() {
		statusLabel.SetText("Fetching peers...")
		go func() {
			list, err := fetchConnectedUsers(&Client)
			fyne.Do(func() {
				if err != nil {
					statusLabel.SetText("Error fetching peers")
					return
				}
				users.Set(list)
				if len(list) == 0 {
					statusLabel.SetText("No peers available — click Refresh to check again")
				} else {
					statusLabel.SetText(fmt.Sprintf("%d peer(s) available", len(list)))
				}
			})
		}()
	}

	refreshBtn := widget.NewButton("Refresh", doRefresh)

	mainWindow.SetContent(container.NewBorder(
		container.NewVBox(
			widget.NewRichTextFromMarkdown("## Select a Peer"),
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			container.NewHBox(refreshBtn, connectBtn),
			statusLabel,
		),
		nil, nil,
		userList,
	))

	doRefresh()
}

func showChatScreen() {
	messages := binding.NewStringList()

	msgList := widget.NewListWithData(messages,
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.Wrapping = fyne.TextWrapWord
			return l
		},
		func(item binding.DataItem, obj fyne.CanvasObject) {
			s, _ := item.(binding.String).Get()
			obj.(*widget.Label).SetText(s)
		},
	)

	input := widget.NewEntry()
	input.SetPlaceHolder("Type a message and press Enter...")

	sendFn := func() {
		text := strings.TrimSpace(input.Text)
		if text == "" {
			return
		}
		input.SetText("")
		outgoingCh <- text
		if text != "REPLAY" && text != "TAMPER" {
			messages.Append("Me: " + text)
			msgList.ScrollToBottom()
		}
	}
	input.OnSubmitted = func(_ string) { sendFn() }

	sendBtn := widget.NewButton("Send", sendFn)
	replayBtn := widget.NewButton("Test: Replay", func() { outgoingCh <- "REPLAY" })
	tamperBtn := widget.NewButton("Test: Tamper", func() { outgoingCh <- "TAMPER" })

	onMessage = func(from, text string) {
		fyne.Do(func() {
			messages.Append(fmt.Sprintf("%s: %s", from, text))
			msgList.ScrollToBottom()
		})
	}

	go func() {
		MessageExchange(&Client)
		fyne.Do(func() {
			dialog.ShowInformation("Session Ended", "The connection was closed.", mainWindow)
		})
	}()

	header := container.NewHBox(
		widget.NewRichTextFromMarkdown(fmt.Sprintf("## Chat with %s", Client.peerId)),
		layout.NewSpacer(),
		replayBtn,
		tamperBtn,
	)

	inputBar := container.NewBorder(nil, nil, nil, sendBtn, input)

	mainWindow.SetContent(container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		container.NewPadded(inputBar),
		nil, nil,
		msgList,
	))
}
