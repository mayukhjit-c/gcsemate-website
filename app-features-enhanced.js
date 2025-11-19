// ============================================================================
// ENHANCED FEATURES - Flashcard UI, AI Quiz Maker, Video Playlist Editing
// ============================================================================

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

    /**
     * Generate quiz using AI
     */
    async generateQuiz(subject, topic, difficulty, questionCount) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            showToast('Generating quiz with AI...', 'info');

            // Use AI Tutor to generate questions
            const prompt = `Generate ${questionCount} ${difficulty} difficulty ${subject} questions about ${topic}. Format as JSON array with: question, options (array of 4), correctAnswer (0-3), explanation.`;

            // Call AI Tutor API
            const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${AI_API_KEY}`, // You'll need to set this
                },
                body: JSON.stringify({
                    model: 'llama-3.1-8b-instant',
                    messages: [
                        {
                            role: 'system',
                            content: 'You are a GCSE quiz generator. Return only valid JSON.',
                        },
                        { role: 'user', content: prompt },
                    ],
                    temperature: 0.7,
                }),
            });

            if (!response.ok) {
                throw new Error('AI generation failed');
            }

            const data = await response.json();
            const questions = JSON.parse(data.choices[0].message.content);

            this.currentQuiz = {
                subject,
                topic,
                difficulty,
                questions,
                startTime: new Date(),
            };

            this.userAnswers = {};
            this.currentQuestionIndex = 0;
            this.retryCount = {};
            this.showAnswers = false;

            this.renderQuiz();
        } catch (error) {
            logError(error, 'AIQuizMaker.generateQuiz');
            // Fallback to placeholder questions
            this.generatePlaceholderQuiz(subject, topic, difficulty, questionCount);
        }
    },

    /**
     * Generate placeholder quiz (fallback)
     */
    generatePlaceholderQuiz(subject, topic, difficulty, questionCount) {
        this.currentQuiz = {
            subject,
            topic,
            difficulty,
            questions: Array.from({ length: questionCount }, (_, i) => ({
                question: `Sample question ${i + 1} about ${topic} in ${subject}?`,
                options: ['Option A', 'Option B', 'Option C', 'Option D'],
                correctAnswer: i % 4,
                explanation: `This is a sample explanation for question ${i + 1}`,
            })),
            startTime: new Date(),
        };

        this.userAnswers = {};
        this.currentQuestionIndex = 0;
        this.retryCount = {};
        this.showAnswers = false;

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

        const question = this.currentQuiz.questions[this.currentQuestionIndex];
        const userAnswer = this.userAnswers[this.currentQuestionIndex];
        const isAnswered = userAnswer !== undefined;
        const isCorrect = isAnswered && userAnswer === question.correctAnswer;
        const retries = this.retryCount[this.currentQuestionIndex] || 0;

        content.innerHTML = `
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl p-6 mb-6">
                <div class="mb-4 flex justify-between items-center">
                    <span class="text-sm font-semibold text-gray-600 dark:text-gray-400">
                        Question ${this.currentQuestionIndex + 1} of ${this.currentQuiz.questions.length}
                    </span>
                    <div class="flex gap-2">
                        <span class="text-xs bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 px-2 py-1 rounded">
                            ${this.currentQuiz.difficulty}
                        </span>
                        ${
                            retries > 0
                                ? `<span class="text-xs bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300 px-2 py-1 rounded">
                            Retries: ${retries}
                        </span>`
                                : ''
                        }
                    </div>
                </div>

                <h3 class="text-xl font-bold text-gray-900 dark:text-gray-100 mb-6">
                    ${escapeHtml(question.question)}
                </h3>

                <div class="space-y-3 mb-6">
                    ${question.options
                        .map((option, idx) => {
                            let buttonClass =
                                'w-full text-left p-4 rounded-lg border-2 transition-all ';
                            let icon = '';

                            if (isAnswered) {
                                if (idx === question.correctAnswer) {
                                    buttonClass +=
                                        'bg-green-100 dark:bg-green-900 border-green-500 text-green-800 dark:text-green-200';
                                    icon = '<i class="fas fa-check-circle mr-2"></i>';
                                } else if (idx === userAnswer && !isCorrect) {
                                    buttonClass +=
                                        'bg-red-100 dark:bg-red-900 border-red-500 text-red-800 dark:text-red-200';
                                    icon = '<i class="fas fa-times-circle mr-2"></i>';
                                } else {
                                    buttonClass +=
                                        'bg-gray-100 dark:bg-gray-700 border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400';
                                }
                            } else {
                                buttonClass +=
                                    'bg-white dark:bg-gray-700 border-gray-300 dark:border-gray-600 hover:border-blue-500 hover:bg-blue-50 dark:hover:bg-blue-900 text-gray-800 dark:text-gray-200 cursor-pointer';
                            }

                            return `
                            <button ${isAnswered ? 'disabled' : `onclick="AIQuizMaker.answerQuestion(${idx})"`}
                                class="${buttonClass}">
                                ${icon}${escapeHtml(option)}
                            </button>
                        `;
                        })
                        .join('')}
                </div>

                ${
                    isAnswered
                        ? `
                    <div class="mb-6 p-4 rounded-lg ${isCorrect ? 'bg-green-50 dark:bg-green-900' : 'bg-red-50 dark:bg-red-900'}">
                        <p class="font-semibold ${isCorrect ? 'text-green-800 dark:text-green-200' : 'text-red-800 dark:text-red-200'} mb-2">
                            ${isCorrect ? '<i class="fas fa-check-circle mr-2"></i>Correct!' : '<i class="fas fa-times-circle mr-2"></i>Incorrect'}
                        </p>
                        <p class="text-sm ${isCorrect ? 'text-green-700 dark:text-green-300' : 'text-red-700 dark:text-red-300'}">
                            ${escapeHtml(question.explanation)}
                        </p>
                    </div>
                `
                        : ''
                }

                <div class="flex gap-2 justify-between">
                    <button onclick="AIQuizMaker.previousQuestion()"
                        ${this.currentQuestionIndex === 0 ? 'disabled' : ''}
                        class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 disabled:opacity-50">
                        <i class="fas fa-chevron-left mr-2"></i>Previous
                    </button>

                    <div class="flex gap-2">
                        ${
                            !isCorrect && isAnswered
                                ? `
                            <button onclick="AIQuizMaker.retryQuestion()"
                                class="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700">
                                <i class="fas fa-redo mr-2"></i>Retry
                            </button>
                        `
                                : ''
                        }

                        ${
                            isAnswered
                                ? `
                            <button onclick="AIQuizMaker.nextQuestion()"
                                class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                                Next<i class="fas fa-chevron-right ml-2"></i>
                            </button>
                        `
                                : ''
                        }
                    </div>
                </div>
            </div>

            ${
                this.currentQuestionIndex === this.currentQuiz.questions.length - 1 &&
                Object.keys(this.userAnswers).length === this.currentQuiz.questions.length
                    ? `
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl p-6 text-center">
                    <h3 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-4">Quiz Complete!</h3>
                    <button onclick="AIQuizMaker.showResults()"
                        class="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-semibold">
                        View Results
                    </button>
                </div>
            `
                    : ''
            }
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
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl p-8 text-center">
                <h2 class="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-4">Quiz Results</h2>
                <div class="text-6xl font-bold mb-4 ${percentage >= 70 ? 'text-green-600' : percentage >= 50 ? 'text-yellow-600' : 'text-red-600'}">
                    ${percentage}%
                </div>
                <p class="text-lg text-gray-600 dark:text-gray-400 mb-6">
                    You got ${correct} out of ${total} questions correct
                </p>

                <div class="space-y-4 mb-6">
                    ${this.currentQuiz.questions
                        .map((q, idx) => {
                            const userAnswer = this.userAnswers[idx];
                            const isCorrect = userAnswer === q.correctAnswer;
                            return `
                            <div class="p-4 rounded-lg ${isCorrect ? 'bg-green-50 dark:bg-green-900' : 'bg-red-50 dark:bg-red-900'}">
                                <p class="font-semibold ${isCorrect ? 'text-green-800 dark:text-green-200' : 'text-red-800 dark:text-red-200'} mb-2">
                                    Q${idx + 1}: ${escapeHtml(q.question)}
                                </p>
                                <p class="text-sm ${isCorrect ? 'text-green-700 dark:text-green-300' : 'text-red-700 dark:text-red-300'}">
                                    Your answer: ${escapeHtml(q.options[userAnswer] || 'Not answered')}
                                    ${!isCorrect ? `| Correct: ${escapeHtml(q.options[q.correctAnswer])}` : ''}
                                </p>
                            </div>
                        `;
                        })
                        .join('')}
                </div>

                <div class="flex gap-2 justify-center">
                    <button onclick="AIQuizMaker.restartQuiz()"
                        class="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-semibold">
                        <i class="fas fa-redo mr-2"></i>Retake Quiz
                    </button>
                    <button onclick="AIQuizMaker.generateNewQuiz()"
                        class="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 font-semibold">
                        <i class="fas fa-plus mr-2"></i>New Quiz
                    </button>
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
                !document.getElementById('videos-page').classList.contains('hidden')
            ) {
                renderVideosPage(allPlaylists);
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
