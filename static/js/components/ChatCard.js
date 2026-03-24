// ChatCard Component
const ChatCard = {
  template: '#chat-card-template',
  props: ['title', 'subtitle', 'icon', 'iconColor', 'data', 'loading'],
  setup(props) {
    const { ref, computed } = Vue;
    const activeTab = ref('reply');

    const pickFirstLine = (text) => {
      if (!text) return '';
      const lines = String(text).split('\n').map(s => s.trim()).filter(Boolean);
      return lines[0] || '';
    };

    const truncate = (s, n = 110) => {
      const str = String(s || '');
      return str.length > n ? str.slice(0, n) + '…' : str;
    };

    const summaryReason = computed(() => {
      if (props.data?.reasoning_trace) {
        const first = pickFirstLine(props.data.reasoning_trace);
        if (first) return truncate(first, 110);
      }
      if (props.data?.response_content) {
        const first = pickFirstLine(props.data.response_content);
        if (first) return truncate(first, 110);
      }
      return props.loading ? '正在分析与判定中…' : '等待运行结果。';
    });

    return { activeTab, summaryReason };
  }
};
