// ============================================================================
// ENHANCED FEATURES - Flashcard UI, AI Quiz Maker, Video Playlist Editing
// ============================================================================

/* global FlashcardSystem, getFirestore, logError, escapeHtml, showPracticeQuestionGeneratorModal */

/**
 * Enhanced Flashcard System with animations, filtering, tags, and saving
 */
const EnhancedFlashcardSystem = {
    ...FlashcardSystem,

    filterTags: [],
    searchQuery: '',
    filteredDecks: [],

    /**
     * Initialize enhanced flashcard UI
     */
    init() {
        this.setupFilterUI();
        this.setupSearchUI();
        this.setupTagSystem();
    },

    /**
     * Setup filter UI
     */
    setupFilterUI() {
        const page = document.getElementById('flashcards-page');
        if (!page) {
            return;
        }

        // Add filter/search bar if not exists
        if (!document.getElementById('flashcard-filters')) {
            const header = page.querySelector('h2').parentElement;
            const filterBar = document.createElement('div');
            filterBar.id = 'flashcard-filters';
            filterBar.className =
                'mb-6 flex flex-col sm:flex-row gap-4 items-start sm:items-center';
            filterBar.innerHTML = `
                <div class="flex-1 w-full sm:w-auto">
                    <input type="text" id="flashcard-search" placeholder="Search decks..."
                        class="w-full px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div class="flex gap-2 flex-wrap">
                    <button onclick="EnhancedFlashcardSystem.showTagFilter()"
                        class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">
                        <i class="fas fa-tags mr-2"></i>Filter by Tags
                    </button>
                    <button onclick="EnhancedFlashcardSystem.clearFilters()"
                        class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">
                        <i class="fas fa-times mr-2"></i>Clear
                    </button>
                </div>
            `;
            header.insertAdjacentElement('afterend', filterBar);

            // Search handler
            document.getElementById('flashcard-search').addEventListener('input', e => {
                this.searchQuery = e.target.value.toLowerCase();
                this.applyFilters();
            });
        }
    },

    /**
     * Setup search UI
     */
    setupSearchUI() {
        // Already handled in setupFilterUI
    },

    /**
     * Setup tag system
     */
    setupTagSystem() {
        // Tags will be stored in deck.tags array
    },

    /**
     * Show tag filter modal
     */
    showTagFilter() {
        const allTags = new Set();
        this.decks.forEach(deck => {
            if (deck.tags && Array.isArray(deck.tags)) {
                deck.tags.forEach(tag => allTags.add(tag));
            }
        });

        const modal = document.createElement('div');
        modal.className =
            'fixed inset-0 z-[20001] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm';
        modal.innerHTML = `
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-md">
                <div class="p-6 border-b border-gray-200 dark:border-gray-700">
                    <h3 class="text-xl font-bold text-gray-800 dark:text-gray-200">Filter by Tags</h3>
                </div>
                <div class="p-6">
                    <div class="flex flex-wrap gap-2">
                        ${Array.from(allTags)
                            .map(
                                tag => `
                            <button onclick="EnhancedFlashcardSystem.toggleTagFilter('${escapeHtml(tag)}')"
                                class="px-3 py-1 rounded-full text-sm ${this.filterTags.includes(tag) ? 'bg-blue-600 text-white' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200'}">
                                ${escapeHtml(tag)}
                            </button>
                        `
                            )
                            .join('')}
                    </div>
                    <div class="mt-4 flex justify-end">
                        <button onclick="this.closest('.fixed').remove()"
                            class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                            Done
                        </button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    },

    /**
     * Toggle tag filter
     */
    toggleTagFilter(tag) {
        const index = this.filterTags.indexOf(tag);
        if (index > -1) {
            this.filterTags.splice(index, 1);
        } else {
            this.filterTags.push(tag);
        }
        this.applyFilters();
        this.showTagFilter(); // Refresh modal
    },

    /**
     * Apply filters
     */
    applyFilters() {
        this.filteredDecks = this.decks.filter(deck => {
            // Search filter
            const matchesSearch =
                !this.searchQuery ||
                deck.name.toLowerCase().includes(this.searchQuery) ||
                deck.subject.toLowerCase().includes(this.searchQuery) ||
                (deck.description && deck.description.toLowerCase().includes(this.searchQuery));

            // Tag filter
            const matchesTags =
                this.filterTags.length === 0 ||
                (deck.tags && this.filterTags.every(tag => deck.tags.includes(tag)));

            return matchesSearch && matchesTags;
        });

        this.renderFilteredDecks();
    },

    /**
     * Render filtered decks
     */
    renderFilteredDecks() {
        const grid = document.getElementById('flashcard-decks-grid');
        if (!grid) {
            return;
        }

        if (this.filteredDecks.length === 0) {
            grid.innerHTML = `
                <div class="col-span-full text-center py-12">
                    <i class="fas fa-search text-6xl text-gray-300 mb-4"></i>
                    <p class="text-gray-600 text-lg mb-2">No decks found</p>
                    <p class="text-gray-500 text-sm">Try adjusting your filters</p>
                </div>
            `;
            return;
        }

        grid.innerHTML = this.filteredDecks.map(deck => this.renderDeckCard(deck)).join('');
    },

    /**
     * Render deck card with tags
     */
    renderDeckCard(deck) {
        const tagsHtml =
            deck.tags && deck.tags.length > 0
                ? `<div class="flex flex-wrap gap-1 mt-2">${deck.tags
                      .map(
                          tag =>
                              `<span class="text-xs bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 px-2 py-1 rounded">${escapeHtml(tag)}</span>`
                      )
                      .join('')}</div>`
                : '';

        return `
            <div class="bg-white/70 dark:bg-gray-800 backdrop-blur-lg border border-white/40 dark:border-gray-700 rounded-xl p-5 shadow-lg hover:shadow-xl transition-all duration-300 cursor-pointer"
                 onclick="FlashcardSystem.openDeck('${deck.id}')">
                <div class="flex items-start justify-between mb-3">
                    <h3 class="text-lg font-bold text-gray-900 dark:text-gray-100">${escapeHtml(deck.name)}</h3>
                    <span class="text-xs bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 px-2 py-1 rounded-full">
                        ${deck.cardCount || 0} cards
                    </span>
                </div>
                <p class="text-sm text-gray-600 dark:text-gray-400 mb-2">${escapeHtml(deck.subject || 'General')}</p>
                ${deck.description ? `<p class="text-xs text-gray-500 dark:text-gray-500 line-clamp-2 mb-2">${escapeHtml(deck.description)}</p>` : ''}
                ${tagsHtml}
                <div class="mt-4 flex gap-2">
                    <button onclick="event.stopPropagation(); FlashcardSystem.startStudy('${deck.id}')"
                        class="flex-1 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-semibold">
                        <i class="fas fa-play mr-1"></i> Study
                    </button>
                    <button onclick="event.stopPropagation(); FlashcardSystem.openDeck('${deck.id}')"
                        class="px-3 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                        <i class="fas fa-edit"></i>
                    </button>
                </div>
            </div>
        `;
    },

    /**
     * Clear filters
     */
    clearFilters() {
        this.filterTags = [];
        this.searchQuery = '';
        document.getElementById('flashcard-search').value = '';
        this.filteredDecks = this.decks;
        this.renderFilteredDecks();
    },

    /**
     * Enhanced flip card with animation
     */
    flipCard() {
        const card = document.getElementById('flashcard-card');
        const front = document.getElementById('flashcard-front');
        const back = document.getElementById('flashcard-back');
        if (!card || !front || !back) {
            return;
        }

        // Add flip animation
        card.style.transform = 'rotateY(180deg)';
        card.style.transition = 'transform 0.6s';

        setTimeout(() => {
            front.classList.toggle('hidden');
            back.classList.toggle('hidden');
            card.style.transform = 'rotateY(0deg)';
        }, 300);
    },

    /**
     * Save flashcard progress
     */
    async saveProgress() {
        if (!this.currentDeck) {
            return;
        }

        try {
            const db = getFirestore();
            const progressRef = db
                .collection('userFlashcards')
                .doc(currentUser.uid)
                .collection('progress')
                .doc(this.currentDeck.id);

            await progressRef.set(
                {
                    lastStudied: firebase.firestore.FieldValue.serverTimestamp(),
                    cardsReviewed: this.currentCardIndex,
                    totalCards: this.currentDeck.cards.length,
                    progress: Math.round(
                        (this.currentCardIndex / this.currentDeck.cards.length) * 100
                    ),
                },
                { merge: true }
            );

            showToast('Progress saved', 'success');
        } catch (error) {
            logError(error, 'EnhancedFlashcardSystem.saveProgress');
        }
    },
};

// Override FlashcardSystem methods
FlashcardSystem.flipCard = EnhancedFlashcardSystem.flipCard.bind(EnhancedFlashcardSystem);

// ============================================================================
// AI QUIZ MAKER WITH AUTO-MARKING
// ============================================================================

const AIQuizMaker = {
    currentQuiz: null,
    userAnswers: {},
    currentQuestionIndex: 0,
    retryCount: {},
    showAnswers: false,
    isGenerating: false,
    loadingInterval: null,
    loadingTipIndex: 0,
    loadingTips: [
        'Warming up the AI engine...',
        'Reviewing GCSE mark schemes...',
        'Picking exam-board grade boundaries...',
        'Crafting clear explanations...',
        'Double-checking distractor options...',
        'Building your personalised quiz...',
    ],

    /**
     * Generate quiz using AI
     */
    async generateQuiz(subject, topic, difficulty, questionCount) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        // Check if user is paid or admin (same check as AI Tutor)
        if (
            !currentUser ||
            (currentUser.tier !== 'paid' && (currentUser.role || '').toLowerCase() !== 'admin')
        ) {
            showToast(
                'AI Quiz Maker is available for Pro users only. Please upgrade to access this feature.',
                'error'
            );
            showPage('features-page');
            return;
        }

        // Check AI request limits (shared with AI Tutor)
        const isAdmin = (currentUser.role || '').toLowerCase() === 'admin';
        const currentRequestCount = window.aiRequestCount || 0;
        const currentMaxRequests = window.aiMaxRequests || currentUser.aiMaxRequestsDaily || 50;
        if (!isAdmin && currentRequestCount >= currentMaxRequests) {
            showToast(
                `You've reached your daily AI request limit (${currentMaxRequests}). Please try again tomorrow.`,
                'error'
            );
            return;
        }

        try {
            showToast('Generating quiz with AI...', 'info');
            this.showLoadingState(subject, topic);

            // Use AI Tutor API endpoint (shared limits)
            const prompt = `Generate ${questionCount} ${difficulty} difficulty GCSE ${subject} questions about ${topic}. Return ONLY a valid JSON array with this exact structure:
[
  {
    "question": "Question text here",
    "options": ["Option A", "Option B", "Option C", "Option D"],
    "correctAnswer": 0,
    "explanation": "Explanation of why the correct answer is right",
    "wrongAnswerExplanations": {
      "0": "Why option A is wrong (if 0 is not correct)",
      "1": "Why option B is wrong (if 1 is not correct)",
      "2": "Why option C is wrong (if 2 is not correct)",
      "3": "Why option D is wrong (if 3 is not correct)"
    }
  }
]
Each question must have exactly 4 options. correctAnswer is 0-3 (index of correct option).
For wrongAnswerExplanations, only include explanations for the 3 wrong options (exclude the correct one).
Explain clearly why each wrong option is incorrect to help students learn from their mistakes.`;

            // Get Firebase Auth token for server-side verification
            const idToken = await firebase.auth().currentUser.getIdToken();

            // AI Tutor has been removed - abort AI-based quiz generation
            showToast('AI Tutor has been removed and is no longer available.', 'error');
            throw new Error('AI Tutor removed');

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || data.error || 'Failed to generate quiz');
            }

            // Update request count (shared with AI Tutor)
            if (window.aiRequestCount !== undefined) {
                window.aiRequestCount = data.requestsUsed || currentRequestCount;
            }
            if (window.aiMaxRequests !== undefined) {
                window.aiMaxRequests = data.maxRequests || currentMaxRequests;
            }

            // Parse AI response - try to extract JSON from markdown code blocks
            let responseText = data.response || '';

            // Try to extract JSON from code blocks
            const jsonMatch = responseText.match(/```(?:json)?\s*(\[[\s\S]*?\])\s*```/);
            if (jsonMatch) {
                responseText = jsonMatch[1];
            } else {
                // Try to find JSON array directly
                const arrayMatch = responseText.match(/\[[\s\S]*?\]/);
                if (arrayMatch) {
                    responseText = arrayMatch[0];
                }
            }

            const questions = JSON.parse(responseText);

            if (!Array.isArray(questions) || questions.length === 0) {
                throw new Error('Invalid quiz format received');
            }

            this.currentQuiz = {
                subject,
                topic,
                difficulty,
                questions: this.prepareQuizQuestions(questions, questionCount),
                startTime: new Date(),
            };

            this.userAnswers = {};
            this.currentQuestionIndex = 0;
            this.retryCount = {};
            this.showAnswers = false;

            this.clearLoadingState();
            this.renderQuiz();
            showToast('Quiz generated successfully!', 'success');
        } catch (error) {
            logError(error, 'AIQuizMaker.generateQuiz');
            showToast('Failed to generate quiz with AI. Using fallback questions.', 'warning');
            this.clearLoadingState();
            // Fallback to placeholder questions
            this.generatePlaceholderQuiz(subject, topic, difficulty, questionCount);
        }
    },

    /**
     * Generate placeholder quiz (fallback)
     */
    generatePlaceholderQuiz(subject, topic, difficulty, questionCount) {
        const placeholderQuestions = Array.from({ length: questionCount }, (_, i) => {
            const correctIdx = i % 4;
            const wrongIndices = [0, 1, 2, 3].filter(idx => idx !== correctIdx);
            return {
                question: `Sample question ${i + 1} about ${topic} in ${subject}?`,
                options: ['Option A', 'Option B', 'Option C', 'Option D'],
                correctAnswer: correctIdx,
                explanation: `This is a sample explanation for question ${i + 1}`,
                wrongAnswerExplanations: {
                    [wrongIndices[0]]: `Option ${String.fromCharCode(65 + wrongIndices[0])} is incorrect because...`,
                    [wrongIndices[1]]: `Option ${String.fromCharCode(65 + wrongIndices[1])} is incorrect because...`,
                    [wrongIndices[2]]: `Option ${String.fromCharCode(65 + wrongIndices[2])} is incorrect because...`,
                },
            };
        });

        this.currentQuiz = {
            subject,
            topic,
            difficulty,
            questions: this.prepareQuizQuestions(placeholderQuestions, questionCount),
            startTime: new Date(),
        };

        this.userAnswers = {};
        this.currentQuestionIndex = 0;
        this.retryCount = {};
        this.showAnswers = false;

        this.clearLoadingState();
        this.renderQuiz();
    },

    /**
     * Render quiz UI
     */
    renderQuiz() {
        const content = document.getElementById('practice-questions-content');
        if (!content || !this.currentQuiz) {
            return;
        }

        this.clearLoadingState();

        const question = this.currentQuiz.questions[this.currentQuestionIndex];
        const userAnswer = this.userAnswers[this.currentQuestionIndex];
        const isAnswered = userAnswer !== undefined;
        const isCorrect = isAnswered && userAnswer === question.correctAnswer;
        const retries = this.retryCount[this.currentQuestionIndex] || 0;
        const progress = Math.round(
            (this.currentQuestionIndex / this.currentQuiz.questions.length) * 100
        );

        const optionButtons = question.options
            .map((option, idx) => {
                const classes = ['quiz-option'];
                let icon = '';

                if (isAnswered) {
                    classes.push('is-disabled');
                    if (idx === question.correctAnswer) {
                        classes.push('is-correct');
                        icon = '<i class="fas fa-check"></i>';
                    } else if (idx === userAnswer && !isCorrect) {
                        classes.push('is-incorrect');
                        icon = '<i class="fas fa-times"></i>';
                    }
                }

                return `
                    <button
                        class="${classes.join(' ')}"
                        ${isAnswered ? 'disabled' : `onclick="AIQuizMaker.answerQuestion(${idx})"`}
                    >
                        <span class="quiz-option__icon">${icon}</span>
                        <span>${escapeHtml(option)}</span>
                    </button>
                `;
            })
            .join('');

        const feedback = isAnswered
            ? `
                <div class="quiz-feedback ${isCorrect ? 'is-correct' : 'is-incorrect'}">
                    <div class="quiz-feedback__status">
                        <span class="quiz-pill ${isCorrect ? 'quiz-pill--success' : 'quiz-pill--error'}">
                            ${isCorrect ? 'Correct' : 'Keep trying'}
                        </span>
                        <p>${escapeHtml(question.explanation || (isCorrect ? 'Nice work!' : "That's not quite right yet."))}</p>
                    </div>
                    ${
                        !isCorrect
                            ? `
                                <div class="quiz-feedback__detail">
                                    <h4>Why your choice was off</h4>
                                    <p>${escapeHtml(
                                        question.wrongAnswerExplanations?.[userAnswer] ||
                                            question.wrongAnswerExplanations?.[
                                                String(userAnswer)
                                            ] ||
                                            ''
                                    )}</p>
                                    <div class="quiz-feedback__answer">
                                        <span>Correct answer</span>
                                        <strong>${escapeHtml(
                                            question.options[question.correctAnswer]
                                        )}</strong>
                                    </div>
                                </div>
                            `
                            : ''
                    }
                </div>
            `
            : '';

        content.innerHTML = `
            <div class="quiz-shell">
                <div class="quiz-progress">
                    <div class="quiz-progress__meta">
                        <span>Question ${this.currentQuestionIndex + 1} of ${
                            this.currentQuiz.questions.length
                        }</span>
                        <div class="quiz-badges">
                            <span class="quiz-pill quiz-pill--primary">${escapeHtml(
                                this.currentQuiz.difficulty
                            )}</span>
                            ${
                                retries > 0
                                    ? `<span class="quiz-pill quiz-pill--warning">Retries: ${retries}</span>`
                                    : ''
                            }
                        </div>
                    </div>
                    <div class="quiz-progress__bar">
                        <div style="width: ${progress}%"></div>
                    </div>
                </div>

                <article class="quiz-card">
                    <header class="quiz-card__header">
                        <p class="quiz-overline">${escapeHtml(this.currentQuiz.subject)} - ${escapeHtml(
                            this.currentQuiz.topic
                        )}</p>
                        <h3 class="quiz-question">${escapeHtml(question.question)}</h3>
                    </header>

                    <div class="quiz-options">
                        ${optionButtons}
                    </div>

                    ${feedback}

                    <div class="quiz-controls">
                        <button class="quiz-button quiz-button--ghost" onclick="AIQuizMaker.previousQuestion()" ${
                            this.currentQuestionIndex === 0 ? 'disabled' : ''
                        }>
                            <i class="fas fa-chevron-left"></i>
                            Previous
                        </button>
                        <div class="quiz-controls__actions">
                            ${
                                !isCorrect && isAnswered
                                    ? `
                                        <button class="quiz-button quiz-button--warning" onclick="AIQuizMaker.retryQuestion()">
                                            <i class="fas fa-redo"></i>
                                            Retry
                                        </button>
                                    `
                                    : ''
                            }
                            ${
                                isAnswered
                                    ? `
                                        <button class="quiz-button" onclick="AIQuizMaker.nextQuestion()">
                                            Next
                                            <i class="fas fa-chevron-right"></i>
                                        </button>
                                    `
                                    : ''
                            }
                        </div>
                    </div>
                </article>

                ${
                    this.currentQuestionIndex === this.currentQuiz.questions.length - 1 &&
                    Object.keys(this.userAnswers).length === this.currentQuiz.questions.length
                        ? `
                        <div class="quiz-card quiz-card--secondary text-center">
                            <h3>Quiz Complete</h3>
                            <p>Great work! Ready to see how you did?</p>
                            <button class="quiz-button" onclick="AIQuizMaker.showResults()">
                                View Results
                            </button>
                        </div>
                    `
                        : ''
                }
            </div>
        `;
    },

    /**
     * Answer question
     */
    answerQuestion(answerIndex) {
        if (!this.currentQuiz) {
            return;
        }

        this.userAnswers[this.currentQuestionIndex] = answerIndex;
        this.renderQuiz();
    },

    /**
     * Retry question
     */
    retryQuestion() {
        if (!this.currentQuiz) {
            return;
        }

        this.retryCount[this.currentQuestionIndex] =
            (this.retryCount[this.currentQuestionIndex] || 0) + 1;
        delete this.userAnswers[this.currentQuestionIndex];
        this.renderQuiz();
    },

    /**
     * Next question
     */
    nextQuestion() {
        if (!this.currentQuiz) {
            return;
        }
        if (this.currentQuestionIndex < this.currentQuiz.questions.length - 1) {
            this.currentQuestionIndex++;
            this.renderQuiz();
        }
    },

    /**
     * Previous question
     */
    previousQuestion() {
        if (!this.currentQuiz) {
            return;
        }
        if (this.currentQuestionIndex > 0) {
            this.currentQuestionIndex--;
            this.renderQuiz();
        }
    },

    /**
     * Show results
     */
    showResults() {
        if (!this.currentQuiz) {
            return;
        }

        const total = this.currentQuiz.questions.length;
        const correct = this.currentQuiz.questions.filter(
            (q, idx) => this.userAnswers[idx] === q.correctAnswer
        ).length;
        const percentage = Math.round((correct / total) * 100);

        const content = document.getElementById('practice-questions-content');
        if (!content) {
            return;
        }

        content.innerHTML = `
            <div class="quiz-shell">
                <div class="quiz-card quiz-card--results text-center">
                    <p class="quiz-overline">Quiz summary</p>
                    <h2 class="quiz-question">${percentage}% accuracy</h2>
                    <p class="quiz-results__meta">${correct} correct answers out of ${total}</p>

                    <div class="quiz-results__breakdown">
                        ${this.currentQuiz.questions
                            .map((q, idx) => {
                                const userAnswer = this.userAnswers[idx];
                                const answeredCorrectly = userAnswer === q.correctAnswer;
                                return `
                                    <div class="quiz-results__item ${
                                        answeredCorrectly ? 'is-correct' : 'is-incorrect'
                                    }">
                                        <span class="quiz-results__badge">Q${idx + 1}</span>
                                        <p>${escapeHtml(q.question)}</p>
                                        <small>
                                            Your answer: ${escapeHtml(
                                                q.options[userAnswer] || 'Not answered'
                                            )}
                                            ${
                                                !answeredCorrectly
                                                    ? ` • Correct: ${escapeHtml(
                                                          q.options[q.correctAnswer]
                                                      )}`
                                                    : ''
                                            }
                                        </small>
                                    </div>
                                `;
                            })
                            .join('')}
                    </div>

                    <div class="quiz-results__actions">
                        <button class="quiz-button" onclick="AIQuizMaker.restartQuiz()">
                            <i class="fas fa-redo"></i>
                            Retake Quiz
                        </button>
                        <button class="quiz-button quiz-button--success" onclick="AIQuizMaker.generateNewQuiz()">
                            <i class="fas fa-plus"></i>
                            New Quiz
                        </button>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Restart quiz
     */
    restartQuiz() {
        if (!this.currentQuiz) {
            return;
        }
        this.userAnswers = {};
        this.currentQuestionIndex = 0;
        this.retryCount = {};
        this.renderQuiz();
    },

    /**
     * Generate new quiz
     */
    generateNewQuiz() {
        showPracticeQuestionGeneratorModal();
    },

    /**
     * Limit and randomize quiz questions for consistent UX
     */
    prepareQuizQuestions(questions, questionCount) {
        if (!Array.isArray(questions)) {
            return [];
        }

        return questions
            .slice(0, questionCount)
            .map(question => this.shuffleQuestionOptions(question));
    },

    /**
     * Shuffle options while keeping the correct answer and explanations aligned
     */
    shuffleQuestionOptions(question) {
        if (!question || !Array.isArray(question.options) || question.options.length < 2) {
            return question;
        }

        const optionMetadata = question.options.map((text, idx) => ({
            text,
            isCorrect: idx === question.correctAnswer,
            wrongExplanation:
                question.wrongAnswerExplanations?.[idx] ??
                question.wrongAnswerExplanations?.[String(idx)] ??
                '',
        }));

        const shuffledOptions = this.shuffleArray(optionMetadata);
        const wrongAnswerExplanations = {};

        shuffledOptions.forEach((option, idx) => {
            if (!option.isCorrect && option.wrongExplanation) {
                wrongAnswerExplanations[idx] = option.wrongExplanation;
            }
        });

        const correctIndex = shuffledOptions.findIndex(option => option.isCorrect);

        return {
            ...question,
            options: shuffledOptions.map(option => option.text),
            correctAnswer: correctIndex >= 0 ? correctIndex : 0,
            wrongAnswerExplanations,
        };
    },

    shuffleArray(items) {
        const array = items.slice();
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
        return array;
    },

    showLoadingState(subject, topic) {
        const content = document.getElementById('practice-questions-content');
        if (!content) {
            return;
        }

        this.isGenerating = true;
        this.loadingTipIndex = 0;
        const tip = this.loadingTips[this.loadingTipIndex];

        content.innerHTML = `
            <div class="quiz-shell">
                <div class="quiz-card quiz-card--loading">
                    <div class="quiz-loader">
                        <span class="quiz-loader__spinner"></span>
                        <p class="quiz-overline">Building your ${escapeHtml(subject)} quiz</p>
                        <h3 class="quiz-question">${escapeHtml(topic)}</h3>
                        <p class="quiz-loader__tip" data-quiz-tip>${tip}</p>
                    </div>
                </div>
            </div>
        `;

        clearInterval(this.loadingInterval);
        this.loadingInterval = setInterval(() => {
            this.loadingTipIndex = (this.loadingTipIndex + 1) % this.loadingTips.length;
            const tipEl = document.querySelector('[data-quiz-tip]');
            if (tipEl) {
                tipEl.textContent = this.loadingTips[this.loadingTipIndex];
            }
        }, 2200);
    },

    clearLoadingState() {
        if (this.loadingInterval) {
            clearInterval(this.loadingInterval);
            this.loadingInterval = null;
        }
        this.isGenerating = false;
    },
};

// ============================================================================
// VIDEO PLAYLIST EDITING
// ============================================================================

const VideoPlaylistEditor = {
    /**
     * Show edit playlist modal
     */
    async showEditModal(playlistId) {
        try {
            const db = getFirestore();
            const playlistDoc = await db.collection('videoPlaylists').doc(playlistId).get();

            if (!playlistDoc.exists) {
                showToast('Playlist not found', 'error');
                return;
            }

            const playlist = { id: playlistId, ...playlistDoc.data() };
            this.renderEditModal(playlist);
        } catch (error) {
            logError(error, 'VideoPlaylistEditor.showEditModal');
            showToast('Failed to load playlist', 'error');
        }
    },

    /**
     * Render edit modal
     */
    renderEditModal(playlist) {
        const modal = document.createElement('div');
        modal.id = 'edit-playlist-modal';
        modal.className =
            'fixed inset-0 z-[20000] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm';
        modal.innerHTML = `
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                <div class="p-6 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
                    <h3 class="text-xl font-bold text-gray-800 dark:text-gray-200">Edit Playlist</h3>
                    <button onclick="document.getElementById('edit-playlist-modal').remove()"
                        class="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <form id="edit-playlist-form" class="p-6 space-y-4" onsubmit="event.preventDefault(); VideoPlaylistEditor.savePlaylist('${playlist.id}');">
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Title</label>
                        <input type="text" id="edit-playlist-title" value="${escapeHtml(playlist.title || '')}" required
                            class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                    </div>
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Playlist URL</label>
                        <input type="url" id="edit-playlist-url" value="${escapeHtml(playlist.url || '')}" required
                            class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                    </div>
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Description</label>
                        <textarea id="edit-playlist-description" rows="3"
                            class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">${escapeHtml(playlist.description || '')}</textarea>
                    </div>
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Tags (comma-separated)</label>
                        <input type="text" id="edit-playlist-tags"
                            value="${(playlist.tags || []).join(', ')}"
                            placeholder="e.g. biology, gcse, revision"
                            class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                        <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">Separate tags with commas</p>
                    </div>
                    <div>
                        <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Category</label>
                        <input type="text" id="edit-playlist-category" value="${escapeHtml(playlist.category || '')}"
                            class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200">
                    </div>
                    <div class="flex justify-end gap-3 pt-4">
                        <button type="button" onclick="document.getElementById('edit-playlist-modal').remove()"
                            class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 font-semibold rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">
                            Cancel
                        </button>
                        <button type="submit"
                            class="px-4 py-2 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700">
                            Save Changes
                        </button>
                    </div>
                </form>
            </div>
        `;
        document.body.appendChild(modal);
    },

    /**
     * Save playlist changes
     */
    async savePlaylist(playlistId) {
        const title = document.getElementById('edit-playlist-title').value.trim();
        const url = document.getElementById('edit-playlist-url').value.trim();
        const description = document.getElementById('edit-playlist-description').value.trim();
        const tagsInput = document.getElementById('edit-playlist-tags').value.trim();
        const category = document.getElementById('edit-playlist-category').value.trim();

        const tags = tagsInput
            .split(',')
            .map(t => t.trim())
            .filter(t => t.length > 0);

        if (!title || !url) {
            showToast('Please fill in all required fields', 'error');
            return;
        }

        try {
            const db = getFirestore();
            await db
                .collection('videoPlaylists')
                .doc(playlistId)
                .update({
                    title,
                    url,
                    description: description || null,
                    tags,
                    category: category || null,
                    updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
                });

            showToast('Playlist updated successfully', 'success');
            document.getElementById('edit-playlist-modal').remove();

            // Refresh playlists if on videos page
            if (
                document.getElementById('videos-page') &&
                !document.getElementById('videos-page').classList.contains('hidden') &&
                typeof window.renderVideosPage === 'function'
            ) {
                window.renderVideosPage(window.allPlaylists || []);
            }
        } catch (error) {
            logError(error, 'VideoPlaylistEditor.savePlaylist');
            showToast('Failed to update playlist', 'error');
        }
    },
};

// Make functions globally available
window.EnhancedFlashcardSystem = EnhancedFlashcardSystem;
window.AIQuizMaker = AIQuizMaker;
window.VideoPlaylistEditor = VideoPlaylistEditor;
