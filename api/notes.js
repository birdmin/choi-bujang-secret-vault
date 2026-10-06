import { createClient } from '@supabase/supabase-js';

export default async function handler(_request, response) {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    response.status(500).json({ error: 'SERVER_CONFIG_ERROR' });
    return;
  }

  const supabase = createClient(supabaseUrl, supabaseSecretKey);

  const { data, error } = await supabase
    .from('notes')
    .select('title, content')
    .order('id', { ascending: true });

  if (error) {
    response.status(500).json({ error: 'NOTES_FETCH_FAILED' });
    return;
  }

  response.setHeader('Cache-Control', 'no-store');
  response.status(200).json({ notes: data });
}
