package logger

import (
	"io"
	"log"
	"os"
)

var (
	InfoLogger  *log.Logger
	WarnLogger  *log.Logger
	ErrorLogger *log.Logger
	DebugLogger *log.Logger
	debugMode   = false
	logFile     *os.File
)

// Init sets up the loggers. If debugMode = true, logs also go to app.log.
func Init(logFilePath string, enableDebug bool) {
	debugMode = enableDebug

	// Default outputs
	infoOut := io.Writer(os.Stdout)
	warnOut := io.Writer(os.Stdout)
	errorOut := io.Writer(os.Stderr)
	debugOut := io.Writer(os.Stdout)

	if enableDebug {
		// Create log file ONLY in debug mode
		var err error
		logFile, err = os.OpenFile(logFilePath,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("could not create debug log file: %v", err)
		}

		// Send logs to both console + file
		infoOut = io.MultiWriter(os.Stdout, logFile)
		warnOut = io.MultiWriter(os.Stdout, logFile)
		errorOut = io.MultiWriter(os.Stderr, logFile)
		debugOut = io.MultiWriter(os.Stdout, logFile)
	}

	flags := log.Ldate | log.Ltime | log.Lshortfile

	InfoLogger = log.New(infoOut, "INFO  ", flags)
	WarnLogger = log.New(warnOut, "WARN  ", flags)
	ErrorLogger = log.New(errorOut, "ERROR ", flags)
	DebugLogger = log.New(debugOut, "DEBUG ", flags)
}

// Permanent INFO-level logs (Always print)
func Info(v ...any) {
    InfoLogger.Println(v...)
}

func Infof(format string, v ...any) {
    InfoLogger.Printf(format, v...)
}

// Conditional DEBUG-level logs (Only print if debugMode is true)
func Debug(v ...any) {
    if debugMode {
        DebugLogger.Println(v...)
    }
}

func Debugf(format string, v ...any) {
    if debugMode {
        DebugLogger.Printf(format, v...)
    }
}

// log warnings to the log terminal or logfile.
func Warn(v ...any) {
	WarnLogger.Println(v...)
}

// log errors to the log terminal or logfile.
func Error(v ...any) {
	ErrorLogger.Println(v...)
}

func Panic(v ...any) {
	if debugMode {
		DebugLogger.Panicln(v...)
	} else {
		InfoLogger.Panicln(v...)
	}
}

// Close should be called on shutdown if debug mode was enabled.
func Close() {
	if logFile != nil {
		_ = logFile.Close()
	}
}
