package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"unicode"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	
	"github.com/grd888/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries *database.Queries
}

func main() {
	const filepathRoot = "."
	const port = "8080"
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: Error loading .env file:", err)
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	dbQueries := database.New(db)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", healthCheckHandler)	

	cfg := &apiConfig{
		dbQueries: dbQueries,
	}
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /admin/metrics", cfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", cfg.resetHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	server := &http.Server{
		Addr: ":" + port,
		Handler: mux,
	}

	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(server.ListenAndServe())
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	html := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
	w.Write([]byte(html))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	type validationRequest struct {
		Body string `json:"body"`
	}
	type cleanedResponse struct {
		CleanedBody string `json:"cleaned_body"`
	}
	type validationErrorResponse struct {
		Error string `json:"error"`
	}
	decoder := json.NewDecoder(r.Body)
	var req validationRequest
	if err := decoder.Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(validationErrorResponse{Error: err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	
	// Check if the chirp is too long (more than 140 characters)
	if len(req.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(validationErrorResponse{Error: "Chirp is too long"})
		return
	}

	// Clean profane words
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	// Split the text into words
	words := strings.Fields(req.Body)
	for i, word := range words {
		// Remove any punctuation for comparison
		cleanWord := strings.TrimFunc(word, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r)
		})
		
		// Check if the word (case-insensitive) is in the profane list
		for _, profane := range profaneWords {
			if strings.EqualFold(cleanWord, profane) {
				// Replace only the word part, keeping any punctuation
				prefix := ""
				suffix := ""
				for j, char := range word {
					if !unicode.IsLetter(char) && !unicode.IsNumber(char) {
						if j < len(cleanWord) {
							prefix += string(char)
						} else {
							suffix += string(char)
						}
					}
				}
				words[i] = prefix + "****" + suffix
				break
			}
		}
	}

	// Join the words back together
	cleanedText := strings.Join(words, " ")

	// Return the cleaned text
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(cleanedResponse{CleanedBody: cleanedText})
}

