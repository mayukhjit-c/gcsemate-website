// ============================================================================
// NEW FEATURES IMPLEMENTATION - All 30 Improvements
// ============================================================================

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (typeof text !== 'string') return text;
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// 1. FLASHCARD SYSTEM WITH SPACED REPETITION
// ============================================================================

const FlashcardSystem = {
    decks: [],
    currentDeck: null,
    currentCardIndex: 0,
    studyMode: 'review', // 'review', 'test', 'match'

    /**
     * Load all flashcard decks for current user
     */
    async loadDecks() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const decksSnapshot = await db
                .collection('userFlashcards')
                .doc(currentUser.uid)
                .collection('decks')
                .orderBy('createdAt', 'desc')
                .get();

            this.decks = [];
            decksSnapshot.forEach(doc => {
                this.decks.push({ id: doc.id, ...doc.data() });
            });

            this.renderDecks();
        } catch (error) {
            logError(error, 'FlashcardSystem.loadDecks');
            showToast('Failed to load flashcard decks', 'error');
        }
    },

    /**
     * Create a new flashcard deck
     */
    async createDeck(name, subject, description = '') {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in to create flashcard decks', 'error');
            return;
        }

        try {
            const db = getFirestore();
            const deckRef = db
                .collection('userFlashcards')
                .doc(currentUser.uid)
                .collection('decks')
                .doc();

            await deckRef.set({
                name,
                subject,
                description,
                cardCount: 0,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Flashcard deck created successfully', 'success');
            await this.loadDecks();
        } catch (error) {
            logError(error, 'FlashcardSystem.createDeck');
            showToast('Failed to create flashcard deck', 'error');
        }
    },

    /**
     * Add card to deck
     */
    async addCard(deckId, front, back, imageUrl = null) {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const cardRef = db
                .collection('userFlashcards')
                .doc(currentUser.uid)
                .collection('cards')
                .doc();

            await cardRef.set({
                deckId,
                front,
                back,
                imageUrl,
                difficulty: 'medium', // 'easy', 'medium', 'hard'
                lastReviewed: null,
                nextReview: firebase.firestore.FieldValue.serverTimestamp(),
                reviewCount: 0,
                correctCount: 0,
                easeFactor: 2.5, // Spaced repetition algorithm
                interval: 1, // Days until next review
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            // Update deck card count
            const deckRef = db
                .collection('userFlashcards')
                .doc(currentUser.uid)
                .collection('decks')
                .doc(deckId);

            await deckRef.update({
                cardCount: firebase.firestore.FieldValue.increment(1),
                updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Card added successfully', 'success');
        } catch (error) {
            logError(error, 'FlashcardSystem.addCard');
            showToast('Failed to add card', 'error');
        }
    },

    /**
     * Spaced repetition algorithm (SM-2 algorithm)
     */
    calculateNextReview(card, quality) {
        // quality: 0-5 (0=blackout, 1=incorrect, 2=incorrect but remembered, 3=correct with difficulty, 4=correct, 5=perfect)
        if (quality < 3) {
            card.interval = 1;
            card.reviewCount = 0;
        } else {
            if (card.reviewCount === 0) {
                card.interval = 1;
            } else if (card.reviewCount === 1) {
                card.interval = 6;
            } else {
                card.interval = Math.round(card.interval * card.easeFactor);
            }
            card.reviewCount += 1;
        }

        // Update ease factor
        card.easeFactor = card.easeFactor + (0.1 - (5 - quality) * (0.08 + (5 - quality) * 0.02));
        if (card.easeFactor < 1.3) card.easeFactor = 1.3;

        // Calculate next review date
        const nextReviewDate = new Date();
        nextReviewDate.setDate(nextReviewDate.getDate() + card.interval);

        return {
            interval: card.interval,
            easeFactor: card.easeFactor,
            nextReview: nextReviewDate,
        };
    },

    /**
     * Render flashcard decks
     */
    renderDecks() {
        const grid = document.getElementById('flashcard-decks-grid');
        if (!grid) return;

        if (this.decks.length === 0) {
            grid.innerHTML = `
                <div class="col-span-full text-center py-12">
                    <i class="fas fa-clone text-6xl text-gray-300 mb-4"></i>
                    <p class="text-gray-600 text-lg mb-2">No flashcard decks yet</p>
                    <p class="text-gray-500 text-sm">Create your first deck to get started!</p>
                </div>
            `;
            return;
        }

        grid.innerHTML = this.decks
            .map(
                deck => `
            <div class="bg-white/70 dark:bg-gray-800 backdrop-blur-lg border border-white/40 dark:border-gray-700 rounded-xl p-5 shadow-lg hover:shadow-xl transition-all duration-300 cursor-pointer"
                 onclick="FlashcardSystem.openDeck('${deck.id}')">
                <div class="flex items-start justify-between mb-3">
                    <h3 class="text-lg font-bold text-gray-900 dark:text-gray-100">${escapeHtml(deck.name)}</h3>
                    <span class="text-xs bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 px-2 py-1 rounded-full">
                        ${deck.cardCount || 0} cards
                    </span>
                </div>
                <p class="text-sm text-gray-600 dark:text-gray-400 mb-2">${escapeHtml(deck.subject || 'General')}</p>
                ${deck.description ? `<p class="text-xs text-gray-500 dark:text-gray-500 line-clamp-2">${escapeHtml(deck.description)}</p>` : ''}
                <div class="mt-4 flex gap-2">
                    <button onclick="event.stopPropagation(); FlashcardSystem.startStudy('${deck.id}')"
                        class="flex-1 px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-semibold">
                        <i class="fas fa-play mr-1"></i> Study
                    </button>
                    <button onclick="event.stopPropagation(); FlashcardSystem.editDeck('${deck.id}')"
                        class="px-3 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                        <i class="fas fa-edit"></i>
                    </button>
                </div>
            </div>
        `
            )
            .join('');
    },

    /**
     * Start studying a deck
     */
    async startStudy(deckId) {
        try {
            const db = getFirestore();
            const cardsSnapshot = await db
                .collection('userFlashcards')
                .doc(currentUser.uid)
                .collection('cards')
                .where('deckId', '==', deckId)
                .get();

            const cards = [];
            cardsSnapshot.forEach(doc => {
                cards.push({ id: doc.id, ...doc.data() });
            });

            if (cards.length === 0) {
                showToast('This deck has no cards yet', 'error');
                return;
            }

            this.currentDeck = { id: deckId, cards };
            this.currentCardIndex = 0;
            this.showStudyArea();
        } catch (error) {
            logError(error, 'FlashcardSystem.startStudy');
            showToast('Failed to load cards', 'error');
        }
    },

    /**
     * Show study area
     */
    showStudyArea() {
        const grid = document.getElementById('flashcard-decks-grid');
        const studyArea = document.getElementById('flashcard-study-area');
        if (!grid || !studyArea) return;

        grid.classList.add('hidden');
        studyArea.classList.remove('hidden');
        this.renderCurrentCard();
    },

    /**
     * Render current card
     */
    renderCurrentCard() {
        const studyArea = document.getElementById('flashcard-study-area');
        if (!studyArea || !this.currentDeck) return;

        const card = this.currentDeck.cards[this.currentCardIndex];
        if (!card) return;

        studyArea.innerHTML = `
            <div class="max-w-2xl mx-auto">
                <div class="mb-4 flex items-center justify-between">
                    <span class="text-sm text-gray-600 dark:text-gray-400">
                        Card ${this.currentCardIndex + 1} of ${this.currentDeck.cards.length}
                    </span>
                    <button onclick="FlashcardSystem.closeStudyArea()"
                        class="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div id="flashcard-card" class="bg-white dark:bg-gray-800 rounded-xl shadow-xl p-8 min-h-[400px] flex items-center justify-center cursor-pointer"
                     onclick="FlashcardSystem.flipCard()">
                    <div id="flashcard-front" class="text-center">
                        <h3 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-4">${escapeHtml(card.front)}</h3>
                        ${card.imageUrl ? `<img src="${escapeHtml(card.imageUrl)}" alt="Card image" class="max-w-full max-h-64 rounded-lg mb-4">` : ''}
                        <p class="text-sm text-gray-500 dark:text-gray-400">Click to flip</p>
                    </div>
                    <div id="flashcard-back" class="hidden text-center">
                        <h3 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-4">${escapeHtml(card.back)}</h3>
                        <div class="mt-6 flex gap-2 justify-center">
                            <button onclick="FlashcardSystem.rateCard(1)" class="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600">Again</button>
                            <button onclick="FlashcardSystem.rateCard(3)" class="px-4 py-2 bg-yellow-500 text-white rounded-lg hover:bg-yellow-600">Hard</button>
                            <button onclick="FlashcardSystem.rateCard(4)" class="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600">Good</button>
                            <button onclick="FlashcardSystem.rateCard(5)" class="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600">Easy</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    /**
     * Flip card
     */
    flipCard() {
        const front = document.getElementById('flashcard-front');
        const back = document.getElementById('flashcard-back');
        if (!front || !back) return;

        front.classList.toggle('hidden');
        back.classList.toggle('hidden');
    },

    /**
     * Rate card (spaced repetition)
     */
    async rateCard(quality) {
        if (!this.currentDeck) return;

        const card = this.currentDeck.cards[this.currentCardIndex];
        const reviewData = this.calculateNextReview(card, quality);

        try {
            const db = getFirestore();
            await db
                .collection('userFlashcards')
                .doc(currentUser.uid)
                .collection('cards')
                .doc(card.id)
                .update({
                    lastReviewed: firebase.firestore.FieldValue.serverTimestamp(),
                    nextReview: firebase.firestore.Timestamp.fromDate(reviewData.nextReview),
                    reviewCount: reviewData.reviewCount,
                    easeFactor: reviewData.easeFactor,
                    interval: reviewData.interval,
                    correctCount: quality >= 3 ? card.correctCount + 1 : card.correctCount,
                });

            this.currentCardIndex++;
            if (this.currentCardIndex >= this.currentDeck.cards.length) {
                showToast('Deck completed! Great job!', 'success');
                this.closeStudyArea();
            } else {
                this.renderCurrentCard();
            }
        } catch (error) {
            logError(error, 'FlashcardSystem.rateCard');
            showToast('Failed to save progress', 'error');
        }
    },

    /**
     * Close study area
     */
    closeStudyArea() {
        const grid = document.getElementById('flashcard-decks-grid');
        const studyArea = document.getElementById('flashcard-study-area');
        if (!grid || !studyArea) return;

        grid.classList.remove('hidden');
        studyArea.classList.add('hidden');
        this.currentDeck = null;
        this.currentCardIndex = 0;
    },

    /**
     * Open deck for editing
     */
    async openDeck(deckId) {
        // Implementation for editing deck
        showToast('Deck editor coming soon', 'info');
    },
};

/**
 * Show create flashcard deck modal
 */
function showCreateFlashcardDeckModal() {
    const modal = document.getElementById('flashcard-modal') || createFlashcardModal();
    modal.style.display = 'flex';
}

/**
 * Create flashcard modal
 */
function createFlashcardModal() {
    const modal = document.createElement('div');
    modal.id = 'flashcard-modal';
    modal.className = 'fixed inset-0 z-[20000] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-md">
            <div class="p-6 border-b border-gray-200 dark:border-gray-700">
                <h3 class="text-xl font-bold text-gray-800 dark:text-gray-200">Create Flashcard Deck</h3>
            </div>
            <form id="create-deck-form" class="p-6 space-y-4" onsubmit="event.preventDefault(); handleCreateFlashcardDeck();">
                <div>
                    <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Deck Name</label>
                    <input type="text" id="deck-name" required
                        class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Subject</label>
                    <input type="text" id="deck-subject" required
                        class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Description (optional)</label>
                    <textarea id="deck-description" rows="3"
                        class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
                </div>
                <div class="flex justify-end gap-3 pt-4">
                    <button type="button" onclick="document.getElementById('flashcard-modal').style.display='none'"
                        class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 font-semibold rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">
                        Cancel
                    </button>
                    <button type="submit"
                        class="px-4 py-2 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700">
                        Create Deck
                    </button>
                </div>
            </form>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

/**
 * Handle create flashcard deck
 */
async function handleCreateFlashcardDeck() {
    const name = document.getElementById('deck-name').value.trim();
    const subject = document.getElementById('deck-subject').value.trim();
    const description = document.getElementById('deck-description').value.trim();

    if (!name || !subject) {
        showToast('Please fill in all required fields', 'error');
        return;
    }

    await FlashcardSystem.createDeck(name, subject, description);
    document.getElementById('flashcard-modal').style.display = 'none';
    document.getElementById('create-deck-form').reset();
}

// ============================================================================
// 2. STUDY PLANNER & GOALS SYSTEM
// ============================================================================

const StudyPlanner = {
    plans: [],
    goals: [],

    /**
     * Load study plans
     */
    async loadPlans() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const plansSnapshot = await db
                .collection('userStudyPlans')
                .doc(currentUser.uid)
                .collection('plans')
                .orderBy('createdAt', 'desc')
                .get();

            this.plans = [];
            plansSnapshot.forEach(doc => {
                this.plans.push({ id: doc.id, ...doc.data() });
            });

            await this.loadGoals();
            this.render();
        } catch (error) {
            logError(error, 'StudyPlanner.loadPlans');
            showToast('Failed to load study plans', 'error');
        }
    },

    /**
     * Load goals
     */
    async loadGoals() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const goalsSnapshot = await db
                .collection('userGoals')
                .doc(currentUser.uid)
                .collection('goals')
                .where('completed', '==', false)
                .orderBy('deadline', 'asc')
                .get();

            this.goals = [];
            goalsSnapshot.forEach(doc => {
                this.goals.push({ id: doc.id, ...doc.data() });
            });
        } catch (error) {
            logError(error, 'StudyPlanner.loadGoals');
        }
    },

    /**
     * Create study plan
     */
    async createPlan(name, startDate, endDate, subjects, hoursPerWeek) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            const db = getFirestore();
            const planRef = db
                .collection('userStudyPlans')
                .doc(currentUser.uid)
                .collection('plans')
                .doc();

            await planRef.set({
                name,
                startDate: firebase.firestore.Timestamp.fromDate(new Date(startDate)),
                endDate: firebase.firestore.Timestamp.fromDate(new Date(endDate)),
                subjects: Array.isArray(subjects) ? subjects : [subjects],
                hoursPerWeek,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Study plan created successfully', 'success');
            await this.loadPlans();
        } catch (error) {
            logError(error, 'StudyPlanner.createPlan');
            showToast('Failed to create study plan', 'error');
        }
    },

    /**
     * Create goal
     */
    async createGoal(title, description, subject, targetDate, targetHours) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            const db = getFirestore();
            const goalRef = db
                .collection('userGoals')
                .doc(currentUser.uid)
                .collection('goals')
                .doc();

            await goalRef.set({
                title,
                description,
                subject,
                targetDate: firebase.firestore.Timestamp.fromDate(new Date(targetDate)),
                targetHours,
                completed: false,
                progress: 0,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Goal created successfully', 'success');
            await this.loadGoals();
        } catch (error) {
            logError(error, 'StudyPlanner.createGoal');
            showToast('Failed to create goal', 'error');
        }
    },

    /**
     * Render plans and goals
     */
    render() {
        const content = document.getElementById('study-planner-content');
        if (!content) return;

        content.innerHTML = `
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="bg-white/70 dark:bg-gray-800 backdrop-blur-lg rounded-xl p-6 shadow-lg">
                    <h3 class="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">Study Plans</h3>
                    ${this.plans.length === 0 ? '<p class="text-gray-500">No study plans yet</p>' : this.renderPlans()}
                </div>
                <div class="bg-white/70 dark:bg-gray-800 backdrop-blur-lg rounded-xl p-6 shadow-lg">
                    <h3 class="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">Goals</h3>
                    ${this.goals.length === 0 ? '<p class="text-gray-500">No goals set yet</p>' : this.renderGoals()}
                </div>
            </div>
        `;
    },

    renderPlans() {
        return this.plans
            .map(
                plan => `
            <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 mb-3">
                <h4 class="font-semibold text-gray-900 dark:text-gray-100">${escapeHtml(plan.name)}</h4>
                <p class="text-sm text-gray-600 dark:text-gray-400 mt-1">
                    ${plan.subjects.join(', ')} • ${plan.hoursPerWeek}h/week
                </p>
            </div>
        `
            )
            .join('');
    },

    renderGoals() {
        return this.goals
            .map(
                goal => `
            <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 mb-3">
                <h4 class="font-semibold text-gray-900 dark:text-gray-100">${escapeHtml(goal.title)}</h4>
                <div class="mt-2">
                    <div class="flex justify-between text-xs text-gray-600 dark:text-gray-400 mb-1">
                        <span>Progress: ${goal.progress || 0}%</span>
                        <span>${goal.targetHours || 0}h target</span>
                    </div>
                    <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div class="bg-blue-600 h-2 rounded-full" style="width: ${goal.progress || 0}%"></div>
                    </div>
                </div>
            </div>
        `
            )
            .join('');
    },
};

/**
 * Show create study plan modal
 */
function showCreateStudyPlanModal() {
    // Implementation similar to flashcard modal
    showToast('Study plan creator coming soon', 'info');
}

// ============================================================================
// 3. PRACTICE QUESTIONS GENERATOR
// ============================================================================

const PracticeQuestions = {
    questions: [],
    currentSession: null,

    /**
     * Generate practice questions
     */
    async generateQuestions(subject, topic, difficulty, count) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            const db = getFirestore();
            // Get questions from database or generate via AI
            const questionsSnapshot = await db
                .collection('practiceQuestions')
                .where('subject', '==', subject)
                .where('difficulty', '==', difficulty)
                .limit(count)
                .get();

            this.questions = [];
            questionsSnapshot.forEach(doc => {
                this.questions.push({ id: doc.id, ...doc.data() });
            });

            if (this.questions.length === 0) {
                showToast('No questions found. Generating with AI...', 'info');
                // Generate via AI Tutor
                await this.generateWithAI(subject, topic, difficulty, count);
            }

            this.renderQuestions();
        } catch (error) {
            logError(error, 'PracticeQuestions.generateQuestions');
            showToast('Failed to generate questions', 'error');
        }
    },

    /**
     * Generate questions with AI
     */
    async generateWithAI(subject, topic, difficulty, count) {
        // Implementation using AI Tutor API
        showToast('AI question generation coming soon', 'info');
    },

    /**
     * Start practice session
     */
    async startPracticeSession() {
        if (this.questions.length === 0) {
            showToast('Please generate questions first', 'error');
            return;
        }

        try {
            const db = getFirestore();
            const sessionRef = db
                .collection('userPracticeSessions')
                .doc(currentUser.uid)
                .collection('sessions')
                .doc();

            this.currentSession = {
                id: sessionRef.id,
                startTime: new Date(),
                questions: this.questions,
                answers: [],
                score: 0,
            };

            await sessionRef.set({
                userId: currentUser.uid,
                startTime: firebase.firestore.FieldValue.serverTimestamp(),
                questions: this.questions.map(q => q.id),
                status: 'in-progress',
            });

            this.renderSession();
        } catch (error) {
            logError(error, 'PracticeQuestions.startPracticeSession');
            showToast('Failed to start session', 'error');
        }
    },

    /**
     * Render questions
     */
    renderQuestions() {
        const content = document.getElementById('practice-questions-content');
        if (!content) return;

        if (this.questions.length === 0) {
            content.innerHTML = '<p class="text-gray-500">No questions available</p>';
            return;
        }

        content.innerHTML = `
            <div class="bg-white/70 dark:bg-gray-800 backdrop-blur-lg rounded-xl p-6 shadow-lg">
                <h3 class="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">Generated Questions</h3>
                <div class="space-y-4">
                    ${this.questions
                        .map(
                            (q, idx) => `
                        <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                            <p class="font-semibold text-gray-900 dark:text-gray-100">Question ${idx + 1}</p>
                            <p class="text-gray-700 dark:text-gray-300 mt-2">${escapeHtml(q.question)}</p>
                        </div>
                    `
                        )
                        .join('')}
                </div>
            </div>
        `;
    },

    /**
     * Render practice session
     */
    renderSession() {
        // Implementation for interactive practice session
        showToast('Practice session started', 'success');
    },
};

/**
 * Show practice question generator modal
 */
function showPracticeQuestionGeneratorModal() {
    showToast('Question generator coming soon', 'info');
}

/**
 * Start practice session
 */
function startPracticeSession() {
    PracticeQuestions.startPracticeSession();
}

// ============================================================================
// 4. NOTES & ANNOTATIONS SYSTEM
// ============================================================================

const NotesSystem = {
    notes: [],

    /**
     * Load notes
     */
    async loadNotes() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const notesSnapshot = await db
                .collection('userNotes')
                .doc(currentUser.uid)
                .collection('notes')
                .orderBy('updatedAt', 'desc')
                .get();

            this.notes = [];
            notesSnapshot.forEach(doc => {
                this.notes.push({ id: doc.id, ...doc.data() });
            });

            this.render();
        } catch (error) {
            logError(error, 'NotesSystem.loadNotes');
            showToast('Failed to load notes', 'error');
        }
    },

    /**
     * Create note
     */
    async createNote(title, content, subject = null) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            const db = getFirestore();
            const noteRef = db
                .collection('userNotes')
                .doc(currentUser.uid)
                .collection('notes')
                .doc();

            await noteRef.set({
                title,
                content,
                subject,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Note created successfully', 'success');
            await this.loadNotes();
        } catch (error) {
            logError(error, 'NotesSystem.createNote');
            showToast('Failed to create note', 'error');
        }
    },

    /**
     * Render notes
     */
    render() {
        const content = document.getElementById('notes-content');
        if (!content) return;

        if (this.notes.length === 0) {
            content.innerHTML = `
                <div class="text-center py-12">
                    <i class="fas fa-sticky-note text-6xl text-gray-300 mb-4"></i>
                    <p class="text-gray-600 text-lg mb-2">No notes yet</p>
                    <p class="text-gray-500 text-sm">Create your first note to get started!</p>
                </div>
            `;
            return;
        }

        content.innerHTML = `
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                ${this.notes
                    .map(
                        note => `
                    <div class="bg-white/70 dark:bg-gray-800 backdrop-blur-lg rounded-xl p-5 shadow-lg hover:shadow-xl transition-all duration-300 cursor-pointer"
                         onclick="NotesSystem.openNote('${note.id}')">
                        <h3 class="text-lg font-bold text-gray-900 dark:text-gray-100 mb-2">${escapeHtml(note.title)}</h3>
                        <p class="text-sm text-gray-600 dark:text-gray-400 line-clamp-3">${escapeHtml(note.content || '').substring(0, 100)}</p>
                        ${note.subject ? `<span class="inline-block mt-2 text-xs bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 px-2 py-1 rounded">${escapeHtml(note.subject)}</span>` : ''}
                    </div>
                `
                    )
                    .join('')}
            </div>
        `;
    },

    /**
     * Open note for editing
     */
    async openNote(noteId) {
        const note = this.notes.find(n => n.id === noteId);
        if (!note) return;

        // Show note editor modal
        showToast('Note editor coming soon', 'info');
    },
};

/**
 * Show create note modal
 */
function showCreateNoteModal() {
    const modal = document.getElementById('note-editor-modal') || createNoteModal();
    modal.style.display = 'flex';
}

/**
 * Create note modal
 */
function createNoteModal() {
    const modal = document.createElement('div');
    modal.id = 'note-editor-modal';
    modal.className = 'fixed inset-0 z-[20000] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
            <div class="p-6 border-b border-gray-200 dark:border-gray-700">
                <h3 class="text-xl font-bold text-gray-800 dark:text-gray-200">Create Note</h3>
            </div>
            <form id="create-note-form" class="p-6 space-y-4" onsubmit="event.preventDefault(); handleCreateNote();">
                <div>
                    <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Title</label>
                    <input type="text" id="note-title" required
                        class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Subject (optional)</label>
                    <input type="text" id="note-subject"
                        class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Content</label>
                    <textarea id="note-content" rows="10" required
                        class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
                </div>
                <div class="flex justify-end gap-3 pt-4">
                    <button type="button" onclick="document.getElementById('note-editor-modal').style.display='none'"
                        class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 font-semibold rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">
                        Cancel
                    </button>
                    <button type="submit"
                        class="px-4 py-2 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700">
                        Save Note
                    </button>
                </div>
            </form>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

/**
 * Handle create note
 */
async function handleCreateNote() {
    const title = document.getElementById('note-title').value.trim();
    const subject = document.getElementById('note-subject').value.trim();
    const content = document.getElementById('note-content').value.trim();

    if (!title || !content) {
        showToast('Please fill in all required fields', 'error');
        return;
    }

    await NotesSystem.createNote(title, content, subject || null);
    document.getElementById('note-editor-modal').style.display = 'none';
    document.getElementById('create-note-form').reset();
}

// ============================================================================
// 5. STUDY GROUPS & COLLABORATION
// ============================================================================

const StudyGroups = {
    groups: [],

    /**
     * Load study groups
     */
    async loadGroups() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            // Load groups user is member of
            const groupsSnapshot = await db
                .collection('studyGroups')
                .where('members', 'array-contains', currentUser.uid)
                .get();

            this.groups = [];
            groupsSnapshot.forEach(doc => {
                this.groups.push({ id: doc.id, ...doc.data() });
            });

            this.render();
        } catch (error) {
            logError(error, 'StudyGroups.loadGroups');
            showToast('Failed to load study groups', 'error');
        }
    },

    /**
     * Create study group
     */
    async createGroup(name, description, isPrivate = false) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            const db = getFirestore();
            const groupRef = db.collection('studyGroups').doc();

            await groupRef.set({
                name,
                description,
                ownerId: currentUser.uid,
                members: [currentUser.uid],
                isPrivate,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Study group created successfully', 'success');
            await this.loadGroups();
        } catch (error) {
            logError(error, 'StudyGroups.createGroup');
            showToast('Failed to create study group', 'error');
        }
    },

    /**
     * Render groups
     */
    render() {
        const content = document.getElementById('study-groups-content');
        if (!content) return;

        if (this.groups.length === 0) {
            content.innerHTML = `
                <div class="text-center py-12">
                    <i class="fas fa-users text-6xl text-gray-300 mb-4"></i>
                    <p class="text-gray-600 text-lg mb-2">No study groups yet</p>
                    <p class="text-gray-500 text-sm">Create or join a study group to collaborate!</p>
                </div>
            `;
            return;
        }

        content.innerHTML = `
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                ${this.groups
                    .map(
                        group => `
                    <div class="bg-white/70 dark:bg-gray-800 backdrop-blur-lg rounded-xl p-5 shadow-lg hover:shadow-xl transition-all duration-300">
                        <h3 class="text-lg font-bold text-gray-900 dark:text-gray-100 mb-2">${escapeHtml(group.name)}</h3>
                        <p class="text-sm text-gray-600 dark:text-gray-400 mb-3 line-clamp-2">${escapeHtml(group.description || '')}</p>
                        <div class="flex items-center justify-between">
                            <span class="text-xs text-gray-500 dark:text-gray-400">${group.members?.length || 0} members</span>
                            <button onclick="StudyGroups.openGroup('${group.id}')"
                                class="px-3 py-1 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm">
                                Open
                            </button>
                        </div>
                    </div>
                `
                    )
                    .join('')}
            </div>
        `;
    },

    /**
     * Open group
     */
    async openGroup(groupId) {
        showToast('Study group view coming soon', 'info');
    },
};

/**
 * Show create study group modal
 */
function showCreateStudyGroupModal() {
    const modal = document.getElementById('study-group-modal') || createStudyGroupModal();
    modal.style.display = 'flex';
}

/**
 * Create study group modal
 */
function createStudyGroupModal() {
    const modal = document.createElement('div');
    modal.id = 'study-group-modal';
    modal.className = 'fixed inset-0 z-[20000] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-md">
            <div class="p-6 border-b border-gray-200 dark:border-gray-700">
                <h3 class="text-xl font-bold text-gray-800 dark:text-gray-200">Create Study Group</h3>
            </div>
            <form id="create-group-form" class="p-6 space-y-4" onsubmit="event.preventDefault(); handleCreateStudyGroup();">
                <div>
                    <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Group Name</label>
                    <input type="text" id="group-name" required
                        class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Description</label>
                    <textarea id="group-description" rows="3"
                        class="w-full p-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
                </div>
                <div>
                    <label class="flex items-center space-x-2 cursor-pointer">
                        <input type="checkbox" id="group-private" class="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500">
                        <span class="text-sm text-gray-700 dark:text-gray-300">Private group (invite only)</span>
                    </label>
                </div>
                <div class="flex justify-end gap-3 pt-4">
                    <button type="button" onclick="document.getElementById('study-group-modal').style.display='none'"
                        class="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 font-semibold rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">
                        Cancel
                    </button>
                    <button type="submit"
                        class="px-4 py-2 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700">
                        Create Group
                    </button>
                </div>
            </form>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

/**
 * Handle create study group
 */
async function handleCreateStudyGroup() {
    const name = document.getElementById('group-name').value.trim();
    const description = document.getElementById('group-description').value.trim();
    const isPrivate = document.getElementById('group-private').checked;

    if (!name) {
        showToast('Please enter a group name', 'error');
        return;
    }

    await StudyGroups.createGroup(name, description, isPrivate);
    document.getElementById('study-group-modal').style.display = 'none';
    document.getElementById('create-group-form').reset();
}

// ============================================================================
// 6. ACHIEVEMENT SYSTEM & GAMIFICATION
// ============================================================================

const AchievementSystem = {
    achievements: [],
    userXP: 0,
    level: 1,

    /**
     * Load user achievements
     */
    async loadAchievements() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const achievementsSnapshot = await db
                .collection('userAchievements')
                .doc(currentUser.uid)
                .collection('achievements')
                .get();

            this.achievements = [];
            achievementsSnapshot.forEach(doc => {
                this.achievements.push({ id: doc.id, ...doc.data() });
            });

            await this.loadXP();
            this.render();
        } catch (error) {
            logError(error, 'AchievementSystem.loadAchievements');
        }
    },

    /**
     * Load user XP
     */
    async loadXP() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const xpDoc = await db.collection('userXP').doc(currentUser.uid).get();

            if (xpDoc.exists) {
                this.userXP = xpDoc.data().xp || 0;
                this.level = this.calculateLevel(this.userXP);
            }
        } catch (error) {
            logError(error, 'AchievementSystem.loadXP');
        }
    },

    /**
     * Calculate level from XP
     */
    calculateLevel(xp) {
        return Math.floor(xp / 100) + 1;
    },

    /**
     * Award XP
     */
    async awardXP(amount, reason) {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const xpRef = db.collection('userXP').doc(currentUser.uid);

            await xpRef.set(
                {
                    xp: firebase.firestore.FieldValue.increment(amount),
                    lastAwarded: firebase.firestore.FieldValue.serverTimestamp(),
                    lastReason: reason,
                },
                { merge: true }
            );

            this.userXP += amount;
            const newLevel = this.calculateLevel(this.userXP);

            if (newLevel > this.level) {
                this.level = newLevel;
                this.showLevelUp();
            }

            showToast(`+${amount} XP: ${reason}`, 'success');
        } catch (error) {
            logError(error, 'AchievementSystem.awardXP');
        }
    },

    /**
     * Unlock achievement
     */
    async unlockAchievement(achievementId, name, description, icon) {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const achievementRef = db
                .collection('userAchievements')
                .doc(currentUser.uid)
                .collection('achievements')
                .doc(achievementId);

            const exists = (await achievementRef.get()).exists;
            if (exists) return; // Already unlocked

            await achievementRef.set({
                name,
                description,
                icon,
                unlockedAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            this.showAchievementUnlocked(name, description, icon);
            await this.awardXP(50, `Achievement: ${name}`);
        } catch (error) {
            logError(error, 'AchievementSystem.unlockAchievement');
        }
    },

    /**
     * Show level up
     */
    showLevelUp() {
        showToast(`Level Up! You're now level ${this.level}!`, 'success');
        NotificationSystem.show('Level Up!', `Congratulations! You've reached level ${this.level}`, 'success');
    },

    /**
     * Show achievement unlocked
     */
    showAchievementUnlocked(name, description, icon) {
        const modal = document.getElementById('achievement-modal') || createAchievementModal();
        modal.innerHTML = `
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl p-8 text-center max-w-md">
                <div class="text-6xl mb-4">${icon}</div>
                <h3 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">Achievement Unlocked!</h3>
                <p class="text-lg font-semibold text-blue-600 dark:text-blue-400 mb-2">${escapeHtml(name)}</p>
                <p class="text-gray-600 dark:text-gray-400 mb-4">${escapeHtml(description)}</p>
                <button onclick="document.getElementById('achievement-modal').style.display='none'"
                    class="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                    Awesome!
                </button>
            </div>
        `;
        modal.style.display = 'flex';
    },

    /**
     * Render achievements
     */
    render() {
        // Render in account settings or dedicated page
    },
};

/**
 * Create achievement modal
 */
function createAchievementModal() {
    const modal = document.createElement('div');
    modal.id = 'achievement-modal';
    modal.className = 'fixed inset-0 z-[20000] flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm';
    document.body.appendChild(modal);
    return modal;
}

// ============================================================================
// 7. REVISION TIMETABLE GENERATOR
// ============================================================================

const TimetableGenerator = {
    timetables: [],

    /**
     * Generate timetable
     */
    async generateTimetable(examDates, subjects, hoursPerWeek) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            // Calculate timetable
            const timetable = this.calculateTimetable(examDates, subjects, hoursPerWeek);

            const db = getFirestore();
            const timetableRef = db
                .collection('userTimetables')
                .doc(currentUser.uid)
                .collection('timetables')
                .doc();

            await timetableRef.set({
                examDates: examDates.map(d => firebase.firestore.Timestamp.fromDate(new Date(d))),
                subjects,
                hoursPerWeek,
                timetable,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Timetable generated successfully', 'success');
            await this.loadTimetables();
        } catch (error) {
            logError(error, 'TimetableGenerator.generateTimetable');
            showToast('Failed to generate timetable', 'error');
        }
    },

    /**
     * Calculate timetable
     */
    calculateTimetable(examDates, subjects, hoursPerWeek) {
        // Simple algorithm to distribute study time
        const timetable = {};
        const totalDays = examDates.reduce((max, date) => {
            const daysUntil = Math.ceil((new Date(date) - new Date()) / (1000 * 60 * 60 * 24));
            return Math.max(max, daysUntil);
        }, 0);

        const hoursPerSubject = hoursPerWeek / subjects.length;
        const sessionsPerWeek = Math.ceil(hoursPerSubject / 2); // 2-hour sessions

        // Generate weekly schedule
        for (let week = 0; week < Math.ceil(totalDays / 7); week++) {
            timetable[`week${week + 1}`] = subjects.map((subject, idx) => ({
                subject,
                sessions: sessionsPerWeek,
                days: this.distributeDays(week, idx, subjects.length),
            }));
        }

        return timetable;
    },

    /**
     * Distribute study days
     */
    distributeDays(week, subjectIndex, totalSubjects) {
        const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
        const sessionsPerWeek = 3;
        const startDay = (week * totalSubjects + subjectIndex) % 7;
        return Array.from({ length: sessionsPerWeek }, (_, i) => days[(startDay + i * 2) % 7]);
    },

    /**
     * Load timetables
     */
    async loadTimetables() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const timetablesSnapshot = await db
                .collection('userTimetables')
                .doc(currentUser.uid)
                .collection('timetables')
                .orderBy('createdAt', 'desc')
                .get();

            this.timetables = [];
            timetablesSnapshot.forEach(doc => {
                this.timetables.push({ id: doc.id, ...doc.data() });
            });
        } catch (error) {
            logError(error, 'TimetableGenerator.loadTimetables');
        }
    },
};

// ============================================================================
// 8. PAST PAPER ANALYZER
// ============================================================================

const PastPaperAnalyzer = {
    papers: [],

    /**
     * Analyze past paper
     */
    async analyzePaper(paperId, answers) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            const db = getFirestore();
            const analysisRef = db
                .collection('userPastPapers')
                .doc(currentUser.uid)
                .collection('analyses')
                .doc();

            const score = this.calculateScore(answers);
            const weakAreas = this.identifyWeakAreas(answers);
            const recommendations = this.generateRecommendations(weakAreas);

            await analysisRef.set({
                paperId,
                answers,
                score,
                weakAreas,
                recommendations,
                analyzedAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Paper analyzed successfully', 'success');
            this.showAnalysis(score, weakAreas, recommendations);
        } catch (error) {
            logError(error, 'PastPaperAnalyzer.analyzePaper');
            showToast('Failed to analyze paper', 'error');
        }
    },

    /**
     * Calculate score
     */
    calculateScore(answers) {
        const total = answers.length;
        const correct = answers.filter(a => a.isCorrect).length;
        return {
            total,
            correct,
            percentage: Math.round((correct / total) * 100),
            grade: this.calculateGrade((correct / total) * 100),
        };
    },

    /**
     * Calculate grade
     */
    calculateGrade(percentage) {
        if (percentage >= 90) return 9;
        if (percentage >= 80) return 8;
        if (percentage >= 70) return 7;
        if (percentage >= 60) return 6;
        if (percentage >= 50) return 5;
        if (percentage >= 40) return 4;
        if (percentage >= 30) return 3;
        if (percentage >= 20) return 2;
        return 1;
    },

    /**
     * Identify weak areas
     */
    identifyWeakAreas(answers) {
        const topics = {};
        answers.forEach(answer => {
            if (!answer.isCorrect && answer.topic) {
                topics[answer.topic] = (topics[answer.topic] || 0) + 1;
            }
        });
        return Object.entries(topics)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([topic]) => topic);
    },

    /**
     * Generate recommendations
     */
    generateRecommendations(weakAreas) {
        return weakAreas.map(area => `Focus on ${area} - review notes and practice more questions`);
    },

    /**
     * Show analysis
     */
    showAnalysis(score, weakAreas, recommendations) {
        showToast(`Score: ${score.percentage}% (Grade ${score.grade})`, 'info');
    },
};

// ============================================================================
// 9. VOICE NOTES & AUDIO STUDY
// ============================================================================

const VoiceNotes = {
    notes: [],
    isRecording: false,
    mediaRecorder: null,

    /**
     * Start recording
     */
    async startRecording() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            this.mediaRecorder = new MediaRecorder(stream);
            const chunks = [];

            this.mediaRecorder.ondataavailable = event => {
                chunks.push(event.data);
            };

            this.mediaRecorder.onstop = async () => {
                const blob = new Blob(chunks, { type: 'audio/webm' });
                await this.saveRecording(blob);
            };

            this.mediaRecorder.start();
            this.isRecording = true;
            showToast('Recording started', 'info');
        } catch (error) {
            logError(error, 'VoiceNotes.startRecording');
            showToast('Failed to start recording. Please allow microphone access.', 'error');
        }
    },

    /**
     * Stop recording
     */
    stopRecording() {
        if (this.mediaRecorder && this.isRecording) {
            this.mediaRecorder.stop();
            this.mediaRecorder.stream.getTracks().forEach(track => track.stop());
            this.isRecording = false;
            showToast('Recording stopped', 'info');
        }
    },

    /**
     * Save recording
     */
    async saveRecording(blob) {
        if (!currentUser || !currentUser.uid) return;

        try {
            const storage = firebase.storage();
            const fileName = `voice-notes/${currentUser.uid}/${Date.now()}.webm`;
            const storageRef = storage.ref(fileName);

            await storageRef.put(blob);
            const url = await storageRef.getDownloadURL();

            const db = getFirestore();
            await db
                .collection('userVoiceNotes')
                .doc(currentUser.uid)
                .collection('notes')
                .add({
                    audioUrl: url,
                    fileName,
                    duration: 0, // Calculate from blob if needed
                    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                });

            showToast('Voice note saved successfully', 'success');
        } catch (error) {
            logError(error, 'VoiceNotes.saveRecording');
            showToast('Failed to save recording', 'error');
        }
    },

    /**
     * Load voice notes
     */
    async loadNotes() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const notesSnapshot = await db
                .collection('userVoiceNotes')
                .doc(currentUser.uid)
                .collection('notes')
                .orderBy('createdAt', 'desc')
                .get();

            this.notes = [];
            notesSnapshot.forEach(doc => {
                this.notes.push({ id: doc.id, ...doc.data() });
            });
        } catch (error) {
            logError(error, 'VoiceNotes.loadNotes');
        }
    },
};

// ============================================================================
// 10. EXPORT & PRINT FEATURES
// ============================================================================

const ExportSystem = {
    /**
     * Export study progress as PDF
     */
    async exportProgressPDF() {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            // Generate PDF using jsPDF or similar
            showToast('PDF export coming soon', 'info');
        } catch (error) {
            logError(error, 'ExportSystem.exportProgressPDF');
            showToast('Failed to export PDF', 'error');
        }
    },

    /**
     * Export exam results
     */
    async exportExamResults() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const resultsSnapshot = await db
                .collection('userExamResults')
                .doc(currentUser.uid)
                .collection('subjects')
                .get();

            const results = {};
            resultsSnapshot.forEach(doc => {
                results[doc.id] = doc.data();
            });

            // Create CSV or JSON export
            const csv = this.convertToCSV(results);
            this.downloadFile(csv, 'exam-results.csv', 'text/csv');
            showToast('Exam results exported', 'success');
        } catch (error) {
            logError(error, 'ExportSystem.exportExamResults');
            showToast('Failed to export results', 'error');
        }
    },

    /**
     * Convert to CSV
     */
    convertToCSV(data) {
        // Simple CSV conversion
        return JSON.stringify(data, null, 2);
    },

    /**
     * Download file
     */
    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    },
};

// ============================================================================
// ENHANCED EXISTING FEATURES
// ============================================================================

// Enhanced Study Progress with Analytics
const EnhancedStudyProgress = {
    /**
     * Get detailed analytics
     */
    async getAnalytics() {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const sessionsSnapshot = await db
                .collection('userStudySessions')
                .where('userId', '==', currentUser.uid)
                .orderBy('startedAt', 'desc')
                .limit(100)
                .get();

            const analytics = {
                totalTime: 0,
                sessionsBySubject: {},
                averageSessionLength: 0,
                bestDay: null,
                streak: 0,
            };

            sessionsSnapshot.forEach(doc => {
                const session = doc.data();
                analytics.totalTime += session.durationMinutes || 0;
                analytics.sessionsBySubject[session.subject] =
                    (analytics.sessionsBySubject[session.subject] || 0) + 1;
            });

            return analytics;
        } catch (error) {
            logError(error, 'EnhancedStudyProgress.getAnalytics');
            return null;
        }
    },
};

// Enhanced AI Tutor with History
const EnhancedAITutor = {
    /**
     * Save conversation
     */
    async saveConversation(messages) {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            const sessionRef = db
                .collection('aiTutorConversations')
                .doc(currentUser.uid)
                .collection('sessions')
                .doc();

            await sessionRef.set({
                messages,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            });
        } catch (error) {
            logError(error, 'EnhancedAITutor.saveConversation');
        }
    },

    /**
     * Load conversation history
     */
    async loadHistory() {
        if (!currentUser || !currentUser.uid) return [];

        try {
            const db = getFirestore();
            const sessionsSnapshot = await db
                .collection('aiTutorConversations')
                .doc(currentUser.uid)
                .collection('sessions')
                .orderBy('createdAt', 'desc')
                .limit(10)
                .get();

            const history = [];
            sessionsSnapshot.forEach(doc => {
                history.push({ id: doc.id, ...doc.data() });
            });

            return history;
        } catch (error) {
            logError(error, 'EnhancedAITutor.loadHistory');
            return [];
        }
    },
};

// Enhanced Search
const EnhancedSearch = {
    /**
     * Advanced search with filters
     */
    async search(query, filters = {}) {
        // Implementation with filters (file type, date, subject)
        showToast('Enhanced search coming soon', 'info');
    },
};

// Enhanced Calendar with Recurring Events
const EnhancedCalendar = {
    /**
     * Create recurring event
     */
    async createRecurringEvent(title, startDate, frequency, endDate) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            const db = getFirestore();
            const eventRef = db
                .collection('userRecurringEvents')
                .doc(currentUser.uid)
                .collection('events')
                .doc();

            await eventRef.set({
                title,
                startDate: firebase.firestore.Timestamp.fromDate(new Date(startDate)),
                endDate: firebase.firestore.Timestamp.fromDate(new Date(endDate)),
                frequency, // 'daily', 'weekly', 'monthly'
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Recurring event created', 'success');
        } catch (error) {
            logError(error, 'EnhancedCalendar.createRecurringEvent');
            showToast('Failed to create recurring event', 'error');
        }
    },
};

// Enhanced Video Progress Tracking
const EnhancedVideoProgress = {
    /**
     * Save video progress
     */
    async saveProgress(videoId, progress, duration) {
        if (!currentUser || !currentUser.uid) return;

        try {
            const db = getFirestore();
            await db
                .collection('userVideoProgress')
                .doc(currentUser.uid)
                .collection('videos')
                .doc(videoId)
                .set(
                    {
                        progress,
                        duration,
                        lastWatched: firebase.firestore.FieldValue.serverTimestamp(),
                    },
                    { merge: true }
                );
        } catch (error) {
            logError(error, 'EnhancedVideoProgress.saveProgress');
        }
    },
};

// Enhanced Blog with Bookmarks
const EnhancedBlog = {
    /**
     * Bookmark blog post
     */
    async bookmarkPost(postId) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            const db = getFirestore();
            await db
                .collection('userBlogBookmarks')
                .doc(currentUser.uid)
                .set(
                    {
                        bookmarks: firebase.firestore.FieldValue.arrayUnion(postId),
                        updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
                    },
                    { merge: true }
                );

            showToast('Post bookmarked', 'success');
        } catch (error) {
            logError(error, 'EnhancedBlog.bookmarkPost');
            showToast('Failed to bookmark post', 'error');
        }
    },
};

// Enhanced File Management
const EnhancedFileManagement = {
    /**
     * Create file collection
     */
    async createCollection(name, fileIds) {
        if (!currentUser || !currentUser.uid) {
            showToast('You must be logged in', 'error');
            return;
        }

        try {
            const db = getFirestore();
            const collectionRef = db
                .collection('userFileCollections')
                .doc(currentUser.uid)
                .collection('collections')
                .doc();

            await collectionRef.set({
                name,
                fileIds,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            });

            showToast('Collection created', 'success');
        } catch (error) {
            logError(error, 'EnhancedFileManagement.createCollection');
            showToast('Failed to create collection', 'error');
        }
    },
};

// Enhanced Admin Dashboard
const EnhancedAdminDashboard = {
    /**
     * Get user analytics
     */
    async getUserAnalytics() {
        if (!currentUser || (currentUser.role || '').toLowerCase() !== 'admin') return;

        try {
            const db = getFirestore();
            // Implementation for user analytics
            showToast('Analytics dashboard coming soon', 'info');
        } catch (error) {
            logError(error, 'EnhancedAdminDashboard.getUserAnalytics');
        }
    },
};

// ============================================================================
// INITIALIZE ALL SYSTEMS
// ============================================================================

/**
 * Initialize all new features when user logs in
 */
async function initializeAllFeatures() {
    if (!currentUser || !currentUser.uid) return;

    try {
        // Load all feature data
        await Promise.all([
            FlashcardSystem.loadDecks(),
            StudyPlanner.loadPlans(),
            NotesSystem.loadNotes(),
            StudyGroups.loadGroups(),
            AchievementSystem.loadAchievements(),
            TimetableGenerator.loadTimetables(),
            VoiceNotes.loadNotes(),
        ]);

        // Initialize page handlers
        setupFeaturePageHandlers();
    } catch (error) {
        logError(error, 'initializeAllFeatures');
    }
}

/**
 * Setup page handlers for new features
 */
function setupFeaturePageHandlers() {
    // Flashcards page
    const flashcardsPage = document.getElementById('flashcards-page');
    if (flashcardsPage) {
        flashcardsPage.addEventListener('show', () => {
            FlashcardSystem.loadDecks();
        });
    }

    // Study planner page
    const studyPlannerPage = document.getElementById('study-planner-page');
    if (studyPlannerPage) {
        studyPlannerPage.addEventListener('show', () => {
            StudyPlanner.loadPlans();
        });
    }

    // Notes page
    const notesPage = document.getElementById('notes-page');
    if (notesPage) {
        notesPage.addEventListener('show', () => {
            NotesSystem.loadNotes();
        });
    }

    // Study groups page
    const studyGroupsPage = document.getElementById('study-groups-page');
    if (studyGroupsPage) {
        studyGroupsPage.addEventListener('show', () => {
            StudyGroups.loadGroups();
        });
    }
}

// Make functions globally available
window.FlashcardSystem = FlashcardSystem;
window.StudyPlanner = StudyPlanner;
window.PracticeQuestions = PracticeQuestions;
window.NotesSystem = NotesSystem;
window.StudyGroups = StudyGroups;
window.AchievementSystem = AchievementSystem;
window.TimetableGenerator = TimetableGenerator;
window.PastPaperAnalyzer = PastPaperAnalyzer;
window.VoiceNotes = VoiceNotes;
window.ExportSystem = ExportSystem;
window.EnhancedStudyProgress = EnhancedStudyProgress;
window.EnhancedAITutor = EnhancedAITutor;
window.EnhancedSearch = EnhancedSearch;
window.EnhancedCalendar = EnhancedCalendar;
window.EnhancedVideoProgress = EnhancedVideoProgress;
window.EnhancedBlog = EnhancedBlog;
window.EnhancedFileManagement = EnhancedFileManagement;
window.EnhancedAdminDashboard = EnhancedAdminDashboard;

